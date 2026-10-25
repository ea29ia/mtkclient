# v7: boot + rootfs-копия `debug_ramdisk/adb_debug.prop` (маршрут R4c)

Дата: 2026-10-25. Ветка `oplus-mt6789-unlock`. **Офлайн: устройство не трогали,
DA не запускали, ничего не флешили, ничего не коммитили.** Все числа получены из
стоковых файлов и из собранных образов в `/tmp/v7/`.

Вход: `docs/notes/reverse/re-init2-escape.md` (маршрут R4c — доказан дизасмом),
`docs/notes/reverse/re-v6-build.md` (v6 и его 43 инварианта),
`docs/notes/PLAN-q1-q2-2026-10-25.md` §F.

Инструмент: `docs/notes/build_v6_dual.py` (`--variant v6|v7`, v7 — дефолт) и
`docs/notes/re_v7_rootfs_prop_test.py` (негативные тесты + воспроизводимость).
Оба — чистый python3 + stdlib; `vendor_boot_extract.py` не менялся.

---

## 0. TL;DR

```
python3 docs/notes/build_v6_dual.py build  --variant v7     # exit 0
python3 docs/notes/build_v6_dual.py verify --variant v7     # exit 0, 47/47 PASS
python3 docs/notes/re_v7_rootfs_prop_test.py                # exit 0, 23/23 PASS
```

| выход | размер | sha256 |
|---|---|---|
| `/tmp/v7/boot_v7.img` (**шить только его**) | 67 108 864 (0x4000000) | `bd0d5dc74a33994a6bb6e0933d5c352b901c7a8cd3319e8f5afafa5e132b9466` |
| `/tmp/v7/vendor_boot_v6.img` (только для сверки, **не шить**) | 67 108 864 | `fb83d015979695b6d4e6ff1f29d9a00a180811d7c9a0877b26f8e0d171fb65a7` (= v6) |

Одна строка: **v7 = v6 boot-образ плюс обычный файл
`debug_ramdisk/adb_debug.prop` внутри уже существующего rootfs-каталога
`debug_ramdisk/`.** Файл читается `PropertyInit()` в *обеих* ветках гейта, поэтому
`ro.adb.secure=0` применяется независимо от `verifiedbootstate`. Партиция под
запись — **только `boot_a`**; `vendor_boot` в v7 не нужен.

---

## 1. Что изменено относительно v5 / v6

### 1.1 Таблица

| | v5 (уже прошит) | v6 | **v7** |
|---|---|---|---|
| boot `/init` P1 @0xF6D14 | `24000014` | `24000014` | `24000014` (без изменений) |
| boot `/force_debuggable` | есть | есть | есть |
| boot `/adb_debug.prop` | есть | есть | есть |
| boot `debug_ramdisk/adb_debug.prop` | — | — | **новый, 81 B** |
| boot cpio записей | 15 (14+trailer) | 16 | **17** |
| vendor_boot P2 + props | — | есть | **не менялся** (файл = v6) |
| кодек boot-рамдиска | gzip | gzip | gzip |
| зависит от `orange` | **да** (обе копии только на tmpfs) | **да** | **нет** |

v5/v6 кладут `/adb_debug.prop` в корень boot-рамдиска; first stage копирует его в
tmpfs `/debug_ramdisk`. Пока tmpfs смонтирован, rootfs-каталог под ним не виден, и
пропа нет нигде, кроме tmpfs. Если гейт пройден (`INIT_FORCE_DEBUGGABLE=="true"`
∧ `IsDeviceUnlocked()`), `PropertyInit()` вызывается до `umount` и читает tmpfs —
это и есть v5/v6. v7 добавляет **вторую** копию в нижний слой, чтобы работала и
else-ветка.

### 1.2 Что именно в cpio (newc, вставка перед `TRAILER!!!`)

| имя | cpio-offset | размер | mode | ino | данные |
|---|---|---|---|---|---|
| `force_debuggable` | `0x300194` | 0 | `0100644` | 300015 | — |
| `adb_debug.prop` | `0x300214` | 81 | `0100644` | 300016 | см. §1.3 |
| **`debug_ramdisk/adb_debug.prop`** | `0x3002E8` | 81 | `0100644` | 300017 | **то же самое** |

`debug_ramdisk` — **стоковая** запись (offset `0x0`, `mode 040755`, `ino 300000`,
size 0), она не пересоздаётся и не меняется; новый файл лишь добавляется внутрь
неё по пути. `TRAILER!!!` сдвигается с `0x300194` на `0x3003C8` (+564 B).

### 1.3 Полезная нагрузка (81 B, sha256 `84bc904d…`)

```
726f2e6164622e7365637572653d300a726f2e64656275676761626c653d310a
726f2e666f7263652e64656275676761626c653d310a706572736973742e737973
2e7573622e636f6e6669673d6164620a
```

```
ro.adb.secure=0
ro.debuggable=1
ro.force.debuggable=1
persist.sys.usb.config=adb
```

Байт-в-байт совпадает с `/adb_debug.prop` (проверяется в `verify`), sha256
`84bc904deff1cc6c7b42e6cccb2e085465250df54f92982001b3c0c313553599`.

---

## 2. Почему это не зависит от `orange` (ground truth дизасма)

Все адреса — VA в `/system/bin/init` (`/tmp/fw/system_init`, 3 085 160 B,
sha256 `a458669ba60984cedf3f0491da6325e2d9f28b51f93bef8522c07308cc8c0037`;
ET_DYN, поэтому VA == файловый offset).

### 2.1 Ветвление в `SecondStageMain`

```
0x001344b0  600400b4  cbz  x0, 0x13453c              ; getenv()==NULL -> else
0x001344b8  72930694  bl   AvbHandle::IsDeviceUnlocked()
0x001344bc  00040036  tbz  w0, #0, 0x13453c           ; ГЕЙТ (orange?)
   ...                                               ; ветка "гейт пройден"
0x00134530  64150094  bl   UmountSecondStageRes()
0x00134534  33150094  bl   UmountDebugRamdisk()
0x00134538  07000014  b    0x134554
0x0013453c                                          ; else (наш случай)
0x00134544  a3930694  bl   unsetenv
0x00134548  2e150094  bl   UmountDebugRamdisk()       ; <-- umount ДО PropertyInit
0x0013454c  b9970094  bl   PropertyInit()
0x00134550  5c150094  bl   UmountSecondStageRes()
```

Ключ: в else-ветке `UmountDebugRamdisk()` (`0x134548`) стоит **перед**
`PropertyInit()` (`0x13454C`).

### 2.2 `UmountDebugRamdisk` = ровно `umount("/debug_ramdisk")`

```
0x00139a18  00f7ffd0  adrp x0, 0x1b000
0x00139a1c  00ec3e91  add  x0, x0, 0xfbb      ; "/debug_ramdisk"
0x00139a28  b67b0694  bl   sym.imp.umount    ; <-- адрес 0x139A28
0x00139a2c  a0000034  cbz  w0, 0x139a40      ; ошибка только логируется
```

Ни `rmdir`, ни `MNT_DETACH`: после вызова под точкой монтирования снова виден
обычный rootfs-каталог из cpio.

### 2.3 Сайт чтения prop-файла в `PropertyLoadBootDefaults`

```
0x00156fe4  e0f6ffb0  adrp x0, 0x33000
0x00156fe8  00b82391  add  x0, x0, 0x8ee      ; "/debug_ramdisk/adb_debug.prop" @0x338EE
0x00156fec  81008052  mov  w1, 4              ; R_OK
0x00156ff0  ec050694  bl   sym.imp.access    ; <-- адрес 0x156FF0
0x00156ff4  60030035  cbnz w0, 0x157060      ; нет файла -> источник пропускается
0x00156ff8  40008052  mov  w0, 2
0x00157028  f6f4ff97  bl   load_properties_from_file(...)
```

`access()`/`load_properties_from_file()` работают **по пути**, а не по inode
tmpfs. После `umount()` путь `/debug_ramdisk/...` — это снова rootfs-каталог, где
лежит наш файл. Поэтому:

| ветка | что видит `PropertyInit` | чем закрывается |
|---|---|---|
| гейт пройден | `PropertyInit` **до** `umount` → tmpfs | `/force_debuggable` + `/adb_debug.prop` (как в v5/v6) |
| гейт не пройден (**orange не нужен**) | `umount` **до** `PropertyInit` → rootfs | **`debug_ramdisk/adb_debug.prop` (новое в v7)** |
| `umount` вернул `EBUSY` | tmpfs остался | снова tmpfs-копия |

SELinux не участвует в выборе: файл читает `init`, контекст `rootfs:s0`
покрыт существующим `(allow init rootfs (file (read getattr map open)))`
(разбор — `re-init2-escape.md` §5.3); `ro.adb.secure` = `build_prop`, значение
принимается через `(allow init property_type (property_service (set)))`.

---

## 3. Сборка и верификация

### 3.1 Команды

```sh
cd ~/mtkclient
python3 docs/notes/build_v6_dual.py build  --variant v7      # -> /tmp/v7/
python3 docs/notes/build_v6_dual.py verify --variant v7      # 47 checks, 0 failed
```

`--variant v7` — дефолт; `--variant v6` оставлен байт-репродуцируемым
(регрессия: те же `af5c10c2…` / `fb83d015…`).

### 3.2 Размеры

| | сток | v6 | **v7** |
|---|---|---|---|
| cpio | 3 146 496 | 3 146 836 | **3 147 060** |
| кодек / размер рамдиска | lz4-legacy 1 649 781 | gzip 1 419 805 | **gzip 1 419 826** |
| конец рамдиска | — | `0x14D2A1D` | **`0x14D2A32`** |
| слот до vbmeta `0x150C000` | 1 654 784 | 1 654 784 | 1 654 784 |
| запас | — | 234 979 | **234 958** |
| header `.ramdisk_size` @0x0C | 0x192C75 | 0x15AA1D | **0x15AA32** |

Сборщик отказывается писать образ, если `len(gzip) > 1 654 784` **или** слот не
равен этой константе (`BOOT_RD_SLOT`), т.е. vbmeta @`0x150C000` не может быть
перекрыта.

### 3.3 Инварианты v7 (23 boot + 21 vendor_boot + 3 внешних = 47)

Старые 43 проверки v6 сохранены (19 boot + 21 vendor_boot + 3 внешних); для v7
добавлены 4 boot-проверки:

```
PASS  boot(v7): debug_ramdisk/ is still a 040755 directory  [mode=0o40755 ino=300000 size=0]
PASS  boot(v7): debug_ramdisk/adb_debug.prop is a 0100644 regular file of 81 B
PASS  boot(v7): debug_ramdisk/adb_debug.prop bytes == /adb_debug.prop (byte-for-byte)
PASS  boot(v7): cpio delta vs stock is exactly the 3 expected entries
```

и обновлены ожидаемые количества (`stock + 3`, набор `{force_debuggable,
adb_debug.prop, debug_ramdisk/adb_debug.prop}`, порядок записей и ino
`300015/300016/300017`). Дополнительно (те же проверки, что у v6, но на v7):

```
PASS  boot: P1 decodes to 'b 0xF6DA4' (VA 0x2F6DA4)
PASS  boot: header/vbmeta/EOF tail byte-identical to stock  [vbmeta@0x150C000, footer=0x150C000/1600]
PASS  boot: ramdisk end < vbmeta offset  [end=0x14D2A32 < 0x150C000, slack=234958]
PASS  boot: cpio prefix is stock bytes except the 3 init bytes  [trailer@0x3003C8 (stock 0x300194, shift 564)]
```

Вне скрипта, независимо:

```
tail identical: True
changed 4K pages: {page 0} U {0x1378 .. 0x150B}  (404 страницы)
first/last differing byte: 0xC .. 0x150AC6F
```

То есть вне заголовка и слота рамдиска образ **побайтно стоковый**, включая
подписанную vbmeta и футер.

### 3.4 Негативные тесты и воспроизводимость (`re_v7_rootfs_prop_test.py`)

```
A. 1 байт в payload rootfs-копии (в КОПИИ, gzip остаётся валидным)
   -> verify exit 1, ровно 1 FAIL:
      FAIL  boot(v7): debug_ramdisk/adb_debug.prop bytes == /adb_debug.prop (byte-for-byte)
      47 checks, 1 failed -> FAIL
B. запись debug_ramdisk/adb_debug.prop удалена из КОПИИ (cpio -224 B)
   -> verify exit 1, 5 FAIL (entry count, presence/format, byte compare, delta, added-set)
C. два полных `build --variant v7` -> идентичные sha256 обоих образов
```

Полный лог — в §7.

---

## 4. Прошивка: **только `boot_a`**

Предусловия как в `termux-host-runbook.md`: Termux native (не proot), root,
`setenforce 0`, OTG; цель — preloader `22d9:0006` (Vol Up + Vol Down + Power + кабель).
`vendor_boot` **не трогаем** — этим снимается риск из `re-v6-build.md` §3.3.

### 4.1 Обёртка (бэкап + readback + авто-откат раздела)

```sh
cd ~/mtkclient
export OPLUS_PATCH_LEVEL=5 OPLUS_SKIP_SLA=0 OPLUS_SKIP_HWINFO=1 OPLUS_NO_DRAIN=1 \
       OPLUS_LEGACY_HOST=1 OPLUS_STORAGE=ufs OPLUS_HWINFO_LATE=1 OPLUS_SBC_PATCH=0 \
       OPLUS_WRITE_BYPASS=1 OPLUS_FLUSH=1

# 1) dry-run: печатает план + 47 PASS, устройство не трогает
python3 docs/notes/build_v6_dual.py flash --variant v7 --vid 0x22d9 --pid 0x0006

# 2) реальная запись boot_a (сначала полный бэкап boot_a)
V7_FLASH_GO=1 python3 docs/notes/build_v6_dual.py flash --variant v7 --vid 0x22d9 --pid 0x0006
```

Обёртка для v7 пишет **один** раздел: readback `boot_a` целиком в
`/tmp/v7/stock_boot_a_<ts>.img`, sha256, затем write, затем readback и побайтное
сравнение; при несовпадении — автоматический откат `boot_a`.

### 4.2 «Голая» команда mtkclient (если обёртка недоступна)

```sh
cd ~/mtkclient
# сначала бэкап (обязательно):
python3 mtk.py --vid 0x22d9 --pid 0x0006 r boot_a /tmp/v7/stock_boot_a_manual.img
sha256sum /tmp/v7/stock_boot_a_manual.img        # ожидается 8c9ef539… (сток)

python3 mtk.py --vid 0x22d9 --pid 0x0006 w boot_a /tmp/v7/boot_v7.img
```

Файл-скрипт (одна строка, ровно один раздел):

```sh
printf 'w boot_a /tmp/v7/boot_v7.img\n' > /tmp/v7/flash_v7.txt
python3 mtk.py --vid 0x22d9 --pid 0x0006 script /tmp/v7/flash_v7.txt
```

`vendor_boot_a` **не писать**: v7 работает без него. Если `vendor_boot_v6.img`
уже был прошит прошлой попыткой — это не мешает (P2-патч безвреден); при полном
возврате к стоку его надо восстановить отдельно (§6).

### 4.3 Readback + md5 после записи

```sh
cd ~/mtkclient
python3 mtk.py --vid 0x22d9 --pid 0x0006 r boot_a /tmp/v7/rb_boot_a.img

md5sum /tmp/v7/rb_boot_a.img /tmp/v7/boot_v7.img
# ожидаемо: bf0cc26ed4feec6be7432ddc60990d51 и для readback, и для образа
sha256sum /tmp/v7/rb_boot_a.img        # bd0d5dc7…  (как у boot_v7.img)
cmp /tmp/v7/rb_boot_a.img /tmp/v7/boot_v7.img   # exit 0
```

Офлайн-проверка прямо по readback (независимый разбор, без доверия к билдеру):

```sh
mkdir -p /tmp/v7/readback
cp /tmp/v7/rb_boot_a.img /tmp/v7/readback/boot_v7.img
cp /tmp/v7/vendor_boot_v6.img /tmp/v7/readback/        # только для сверки
python3 docs/notes/build_v6_dual.py verify --variant v7 -o /tmp/v7/readback
# ожидаемо: 47 checks, 0 failed -> PASS
```

---

## 5. Ожидаемый результат на устройстве

После `boot_v7.img` в `boot_a` (кабель отключён при старте, потом подключён):

```sh
adb devices -l
# ожидается: <serial>  device usb:... product:... model:...   <- "device", НЕ "unauthorized"

adb shell getprop ro.adb.secure        # 0
adb shell getprop ro.debuggable        # 1
adb shell id                           # uid=0(root) gid=0(root) ...
```

Диагностика (не обязательна для успеха):

```sh
adb shell getprop ro.boot.verifiedbootstate      # green / yellow / orange
adb shell ls -l /debug_ramdisk                   # после umount тут пусто/dir
adb shell ls -l /force_debuggable /adb_debug.prop && cat /adb_debug.prop
adb shell getprop | grep -E 'adb.secure|debuggable|usb.config'
```

Важно: при **не**-orange v7 всё равно даёт `ro.adb.secure=0` (через rootfs-копию).
Если `verifiedbootstate` окажется `orange`, маршрут тоже работает — но тогда
хватило бы и v5; это не отменяет результата, а объясняет, почему прошлые попытки
могли падать по другой причине.

Порядок файлов в `PropertyLoadBootDefaults`: `/debug_ramdisk/adb_debug.prop` —
последний (№13), поэтому его значения перекрывают `/system/build.prop`
(`re-init-prop-gate.md` §4.2).

---

## 6. Откат

```sh
cd ~/mtkclient
# a) бэкап, снятый обёрткой (точное имя печатается при прошивке):
python3 mtk.py --vid 0x22d9 --pid 0x0006 w boot_a /tmp/v7/stock_boot_a_<ts>.img

# b) или исходный сток (сверить sha256 ПЕРЕД записью):
sha256sum docs/notes/rmx3630-lk/boot.img          # 8c9ef5391a6f90fa43bcf46cdd4eeb4bdbae9b55595b9bdb2e4d84c20d45a8c9
python3 mtk.py --vid 0x22d9 --pid 0x0006 w boot_a docs/notes/rmx3630-lk/boot.img

# без DA (загрузчик разблокирован):
fastboot flash boot_a docs/notes/rmx3630-lk/boot.img
```

Если прошлой попыткой был прошит `vendor_boot_a`, для полного стока:

```sh
sha256sum /tmp/fw/vendor_boot.img                 # 1fa1e890275b176b85ef2c7186910d497f14f1642013a0a42c862b60977e7ab4
python3 mtk.py --vid 0x22d9 --pid 0x0006 w vendor_boot_a /tmp/fw/vendor_boot.img
```

Единственная изменяемая v7 партиция — `boot_a`; откат не требует eMMC/UFS-образов
и не зависит от `seccfg`.

---

## 7. Логи приёмки (exit 0)

### 7.1 build v7

```
$ python3 docs/notes/build_v6_dual.py build --variant v7
[*] variant v7
[*] stock boot.img         : 67108864 B sha256 8c9ef5391a6f90fa43bcf46cdd4eeb4bdbae9b55595b9bdb2e4d84c20d45a8c9
    P1 @0xF6D14: 93040036 -> 24000014 (b 0x2F6DA4)
    ramdisk: lz4-legacy 1649781 B -> gzip 1419826 B (slot 1654784 B, slack 234958 B)
    layout: kernel 0x1376ECD +0x1000, ramdisk @0x1378000, vbmeta @0x150C000 (tail verbatim)
    cpio entries: 14 -> 17   (1.0s)
    added entries: force_debuggable, adb_debug.prop, debug_ramdisk/adb_debug.prop
[*] stock vendor_boot.img : 67108864 B sha256 1fa1e890275b176b85ef2c7186910d497f14f1642013a0a42c862b60977e7ab4
    P2 @0xF1710: 33050036 -> 29000014 (b 0xF17B4)
    ramdisk: lz4-legacy 35835345 B -> 36602570 B (9/11 stock 8 MiB blocks reused verbatim, 12465236 B recompressed)
    layout: ramdisk@0x1000 dtb@0x22EA000 table@0x2319000 vbmeta@0x231A000 size=67108864
    cpio entries: 915 -> 917   (24.4s)
[*] LK in-memory initrd: vendor 36602570 + boot 1419826 + 0x800 = 38024444 <= 67108864: True
[+] wrote /tmp/v7/boot_v7.img (67108864 B sha256 bd0d5dc74a33994a6bb6e0933d5c352b901c7a8cd3319e8f5afafa5e132b9466)
[+] wrote /tmp/v7/vendor_boot_v6.img (67108864 B sha256 fb83d015979695b6d4e6ff1f29d9a00a180811d7c9a0877b26f8e0d171fb65a7)
[!] v7: flash boot_a ONLY; vendor_boot_v6.img is reference/regression parity (do NOT flash it)
[*] now run: python3 docs/notes/build_v6_dual.py verify --variant v7
EXIT=0
```

### 7.2 verify v7 (47/47)

```
$ python3 docs/notes/build_v6_dual.py verify --variant v7
PASS  boot: magic/header v4/header_size 0x630  [hv=4 hsz=0x630]
PASS  boot: kernel_size unchanged  [0x1376ECD]
PASS  boot: ramdisk offset = align(0x1000+kernel)  [0x1378000]
PASS  boot: size field == real ramdisk bytes  [ramdisk_size=1419826]
PASS  boot: kernel bytes byte-identical to stock
PASS  boot: header/vbmeta/EOF tail byte-identical to stock  [vbmeta@0x150C000, footer=0x150C000/1600]
PASS  boot: AVB0 at vbmeta offset, AVBf in last 64 B
PASS  boot: ramdisk end < vbmeta offset  [end=0x14D2A32 < 0x150C000, slack=234958]
PASS  boot: no nonzero bytes outside header/kernel/ramdisk/vbmeta sections
PASS  boot: ramdisk decodes (gzip), cpio parses  [3147060 B cpio, 17 entries]
PASS  boot: cpio entry count == stock + 3  [14 -> 17 (variant v7)]
PASS  boot: cpio prefix is stock bytes except the 3 init bytes  [trailer@0x3003C8 (stock 0x300194, shift 564) diffs=['0xf6e78', '0xf6e79', '0xf6e7b']]
PASS  boot: /init is a regular file of 3143536 B
PASS  boot: P1 bytes at 0xF6D14 are 24000014  [24000014]
PASS  boot: P1 decodes to 'b 0xF6DA4' (VA 0x2F6DA4)  [file target=0xF6DA4]
PASS  boot: /init differs from stock only in the 4-byte patch site  [bytes=['0xf6d14', '0xf6d15', '0xf6d17']]
PASS  boot: /force_debuggable present, empty, 0100644  [mode=0o100644]
PASS  boot: /adb_debug.prop content == expected 81 B  [84bc904deff1cc6c]
PASS  boot: every stock entry preserved (no /prop.default, build.prop intact)  [missing=[] changed=[] added=['adb_debug.prop', 'debug_ramdisk/adb_debug.prop', 'force_debuggable']]
PASS  boot(v7): debug_ramdisk/ is still a 040755 directory  [mode=0o40755 ino=300000 size=0]
PASS  boot(v7): debug_ramdisk/adb_debug.prop is a 0100644 regular file of 81 B  [mode=0o100644 size=81]
PASS  boot(v7): debug_ramdisk/adb_debug.prop bytes == /adb_debug.prop (byte-for-byte)  [81 B sha256 84bc904deff1cc6c]
PASS  boot(v7): cpio delta vs stock is exactly the 3 expected entries  [added=['adb_debug.prop', 'debug_ramdisk/adb_debug.prop', 'force_debuggable'] inodes=[300015, 300016, 300017]]
PASS  vendor_boot: file size == 64 MiB and <= partition  [67108864 B]
PASS  vendor_boot: still v4/page 4096/one PLATFORM fragment
PASS  vendor_boot: kernel/tags/dtb addrs, cmdline and name unchanged
PASS  vendor_boot: header page identical except vendor_ramdisk_size@24  [hdr_size=0x850]
PASS  vendor_boot: ramdisk@0x1000, dtb/table/vbmeta page-aligned in order  [dtb@0x22EA000 table@0x2319000 vbmeta@0x231A000]
PASS  vendor_boot: table entry points exactly at ramdisk, size == header size  [size=36602570 off=0]
PASS  vendor_boot: table type/name/board_id unchanged (PLATFORM, all-zero board)
PASS  vendor_boot: dtb bytes byte-identical to stock  [sha256 66d8b85d0797c632]
PASS  vendor_boot: gap between ramdisk and dtb is zero padding
PASS  vendor_boot: no nonzero bytes outside header/ramdisk/dtb/table/vbmeta
PASS  vendor_boot: embedded vbmeta is unsigned (alg NONE) and self-consistent  [name=vendor_boot image_size=36806656 digest=9ff8e4fb947ac67b]
PASS  vendor_boot: AVB footer -> same vbmeta offset, size 640, partition end  [orig=0x231A000 off=0x231A000]
PASS  vendor_boot: ramdisk decodes (lz4-legacy), cpio parses  [87962708 B cpio, 917 entries]
PASS  vendor_boot: cpio entry count == stock + 2  [915 -> 917]
PASS  vendor_boot: cpio prefix is stock bytes except the 3 init bytes  [trailer@0x53E33B8 (stock 0x53E3264, shift 340) diffs=['0x3197684', '0x3197685', '0x3197687']]
PASS  vendor_boot: /init is still the untouched symlink -> /system/bin/init  [mode=0o120750 body=b'/system/bin/init']
PASS  vendor_boot: P2 bytes at 0xF1710 are 29000014  [29000014]
PASS  vendor_boot: P2 decodes to 'b 0xF17B4'  [target=0xF17B4]
PASS  vendor_boot: system/bin/init differs only in the 4-byte patch site  [bytes=['0xf1710', '0xf1711', '0xf1713']]
PASS  vendor_boot: /force_debuggable + /adb_debug.prop at the cpio root  [props=81 B]
PASS  vendor_boot: every stock entry preserved; only the 2 files added  [missing=[] changed=[] added=['adb_debug.prop', 'force_debuggable']]
PASS  vendor_boot_extract.py --info exits 0  [rc=0]
PASS  vendor_boot_extract.py --list exits 0  [rc=0]
PASS  vendor_boot_extract.py --list shows the 2 added entries and 917 entries  [['force_debuggable', 'adb_debug.prop'], 917 found]

47 checks, 0 failed -> PASS
EXIT=0
```

### 7.3 v6 не сломан (43/43, те же байты)

```
$ python3 docs/notes/build_v6_dual.py build --variant v6 -o /tmp/v6_regress
[+] wrote /tmp/v6_regress/boot_v6.img (67108864 B sha256 af5c10c20d3b3855335fb4dee36da20996316f8c643f22212ecc9b6acd16121a)
[+] wrote /tmp/v6_regress/vendor_boot_v6.img (67108864 B sha256 fb83d015979695b6d4e6ff1f29d9a00a180811d7c9a0877b26f8e0d171fb65a7)
EXIT=0

$ python3 docs/notes/build_v6_dual.py verify --variant v6 -o /tmp/v6_regress
43 checks, 0 failed -> PASS
EXIT=0

$ sha256sum /tmp/v7/boot_v7.img
bd0d5dc74a33994a6bb6e0933d5c352b901c7a8cd3319e8f5afafa5e132b9466  /tmp/v7/boot_v7.img
```

### 7.4 негативные тесты + воспроизводимость

```
$ python3 docs/notes/re_v7_rootfs_prop_test.py
PASS  baseline verify --variant v7 exits 0  [rc=0]
PASS  baseline reports 47 checks, 0 failed  [47 checks, 0 failed -> PASS]
PASS  copy source contains exactly one debug_ramdisk/adb_debug.prop  [1]
PASS  corrupted copy keeps the entry at 81 B, payload differs in 1 byte  [81 B]
PASS  corrupted copy's /adb_debug.prop is still pristine
PASS  A: verify exits 1  [rc=1]
PASS  A: exactly 1 failing check  [FAIL  boot(v7): debug_ramdisk/adb_debug.prop bytes == /adb_debug.prop (byte-for-byte)  [81 B sha256 e04b28e86850ca08]]
PASS  A: the failing check is the rootfs prop byte comparison
PASS  A: failure count line says 1 failed  [47 checks, 1 failed -> FAIL]
PASS  dropped exactly one entry  [1]
PASS  rebuilt cpio is 224 B smaller (entry header 140 + padded data 84)  [3147060 -> 3146836]
PASS  B: verify exits 1  [rc=1]
PASS  B: entry-count check fails
PASS  B: presence/format check fails
PASS  B: byte-comparison check fails
PASS  B: >1 failing check (delta also broken)  [5 fails]
PASS  C: build #1 exits 0  [rc=0]
PASS  C: build #2 exits 0  [rc=0]
PASS  C: both runs produced both images  [['boot_v7.img', 'vendor_boot_v6.img']]
PASS  C: boot_v7.img sha256 identical across runs  [bd0d5dc74a33994a6bb6e0933d5c352b901c7a8cd3319e8f5afafa5e132b9466]
PASS  C: vendor_boot_v6.img sha256 identical across runs  [fb83d015979695b6d4e6ff1f29d9a00a180811d7c9a0877b26f8e0d171fb65a7]
PASS  C: boot sha256 == the shipped /tmp/v7 build
PASS  C: vendor_boot sha256 == the historical v6 hash fb83d015...
23 checks, 0 failed -> PASS
EXIT=0
```

### 7.5 flash dry-run (устройство не тронуто)

```
$ python3 docs/notes/build_v6_dual.py flash --variant v7 --vid 0x22d9 --pid 0x0006
...
47 checks, 0 failed -> PASS
[*] plan: write /tmp/v7/boot_v7.img (67108864 B sha256 bd0d5dc7...) -> boot_a
[dryrun] no device touched. Re-run with V7_FLASH_GO=1 to write
EXIT=0
```

---

## 8. Если после прошивки всё ещё `unauthorized`

Собрать и приложить (по порядку, без догадок):

1. **Состояние LK без Android** — гейт и `verifiedbootstate`:
   ```sh
   fastboot getvar secure          # yes/no — тот же валидированный геттер, что у boot-решения
   fastboot getvar unlocked        # yes/no
   fastboot getvar all
   python3 docs/notes/lk_state_probe.py --plan
   python3 docs/notes/lk_state_probe.py --decode fastboot_transcript.txt
   ```
   `getvar` разрешён и на заблокированном устройстве. Если `secure=yes`/`unlocked=no`,
   LK не выставит `orange` — но **для v7 это не важно**; это объясняет, почему
   могли падать v5/v6.
2. **Действительно ли на устройстве v7**: readback `boot_a` + `verify --variant v7`
   + `sha256sum`/`cmp` (§4.3). Если readback ≠ образ — виновата запись, а не init.
3. **ADB-транспорт**:
   ```sh
   adb kill-server; adb start-server
   adb devices -l
   ADB_TRACE=all adb devices 2>&1 | tail -50     # видно, доходит ли до AUTH_SIGNATURE
   lsusb ; termux-usb -l ; ls /sys/bus/usb/devices
   ```
   `unauthorized` при рабочем `adbd` = `ro.adb.secure` всё ещё 1 **или** `adbd`
   не перечитал проп (см. п.4).
4. **Загрузился ли prop-файл** (нужен хоть какой-то root-доступ; если его нет —
   только офлайн-факты из п.2):
   ```sh
   adb shell getprop ro.adb.secure            # 1 => prop не применился
   adb shell getprop ro.boot.verifiedbootstate
   adb shell ls -l /debug_ramdisk /debug_ramdisk/adb_debug.prop /adb_debug.prop
   adb shell dmesg | grep -iE 'debug_ramdisk|adb_debug|property'
   adb shell 'cat /proc/last_kmsg 2>/dev/null | tail -100'
   ```
   Диагностические маркеры:
   * `/debug_ramdisk/adb_debug.prop` отсутствует, хотя readback верный →
     файл не распаковался из cpio (проверить `cpio`-энтри в образе: `verify`);
   * файл есть, `ro.adb.secure` = 1 → `PropertyInit` не дошёл до источника №13
     (перепроверить порядок prop-файлов на этой прошивке);
   * `ro.adb.secure` = 0, а `adb` всё равно `unauthorized` → проблема на стороне
     `adbd`/`adb_keys` (это уже не R4c: см. `re-adbd-apex-route.md`).
5. **Экран/загрузка**: `fastboot getvar version-bootloader`, `getprop
   ro.build.fingerprint` (если есть shell), скриншот/`pstore` при bootloop.

Ключевой фальсификатор для R4c: `ro.adb.secure` = 0 при
`verifiedbootstate != orange`. Если он 0, а adb всё равно не пускает — маршрут
сработал, и искать надо в `adbd` (`ro.adb.secure` читается adbd один раз при
старте; помогает `stop adbd; start adbd` при root-shell).

---

## 9. Ограничения / честные оговорки

1. Всё проверено **офлайн**. «PASS» = «образ собран по контракту и
   самосогласован», а не «телефон загрузится» и не «adb станет device».
2. Подпись AVB boot не воспроизводима (ключ OPLUS), хвост `[0x150C000..EOF)`
   скопирован побайтно — ровно ситуация v5, которая на этом аппарате грузилась
   при unlocked + `ALLOW_VERIFICATION_ERRORS`.
3. Механизм R4c опирается на порядок инструкций `0x134548`/`0x13454C` в
   **этом** `/system/bin/init` (sha256 `a458669b…`). Другая прошивка = другая
   раскладка; перед переносом — перепроверить дизасм.
4. Если `umount("/debug_ramdisk")` вернёт ошибку, tmpfs останется и сработает
   tmpfs-копия (поэтому в cpio лежат **обе**). Если first stage вообще не
   монтирует tmpfs — rootfs-копия видна сразу, маршрут всё равно работает.
5. `ro.adb.secure` перекрывается последним файлом map; порядок источников
   проверен на этом образе (`re-init-prop-gate.md` §4.2).
6. `vendor_boot_v6.img` в `/tmp/v7/` — только для сверки/регрессии. Шить его в
   рамках v7 **не нужно и не следует**.

---

## 10. Файлы

| файл | назначение |
|---|---|
| `docs/notes/build_v6_dual.py` | `build`/`verify`/`flash`, `--variant v6|v7` (v7 — дефолт) |
| `docs/notes/re_v7_rootfs_prop_test.py` | негативные тесты A/B + воспроизводимость C |
| `docs/notes/reverse/re-v7-rootfs-prop.md` | этот отчёт |
| `/tmp/v7/boot_v7.img` | единственный образ для прошивки (не в репозитории) |
| `/tmp/v7/vendor_boot_v6.img` | копия v6 vendor_boot, только для сверки |

Не менялись: `vendor_boot_extract.py`, `lk_state_probe.py`, `seccfg_validate.py`,
`re_init2_spec_test.py`, `verify_adb_state.sh`, все трекаемые бинарники
(`docs/notes/rmx3630-*/**`). Ничего не коммитилось.
