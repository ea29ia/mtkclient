# v6: dual-ramdisk build (boot + vendor_boot) — сборка и офлайн-верификация

Дата: 2026-10-25. Ветка `oplus-mt6789-unlock`. **Офлайн: устройство не трогали,
DA не запускали, ничего не флешили.** Все числа ниже получены из стоковых файлов
и из собранных образов в `/tmp/v6/`.

Инструмент: `docs/notes/build_v6_dual.py` (чистый python3 + stdlib; LZ4
legacy-декодер импортируется из `docs/notes/vendor_boot_extract.py`, который
**не менялся**). Образы в репозиторий не коммитятся.

Контракт: `PLAN-q1-q2-2026-10-25.md` §F. Контекст: `re-vendor-boot-q1.md`
(чей `/init` побеждает), `re-init-prop-gate.md` (P1/P2 и гейт
`verifiedbootstate=="orange"`).

---

## 0. TL;DR

```
python3 docs/notes/build_v6_dual.py build     # exit 0
python3 docs/notes/build_v6_dual.py verify    # exit 0, 43/43 PASS
```

| выход | размер | sha256 |
|---|---|---|
| `/tmp/v6/boot_v6.img` | 67 108 864 (0x4000000) | `af5c10c20d3b3855335fb4dee36da20996316f8c643f22212ecc9b6acd16121a` |
| `/tmp/v6/vendor_boot_v6.img` | 67 108 864 (0x4000000) | `fb83d015979695b6d4e6ff1f29d9a00a180811d7c9a0877b26f8e0d171fb65a7` |

Оба рамдиска пропатчены (P1 + P2) и в оба добавлены `/force_debuggable` и
`/adb_debug.prop`, поэтому результат не зависит от того, чей `/init` исполнится.
Сборка детерминирована: повторный `build` даёт те же sha256 (проверено).

---

## 1. Входы (не менялись)

| файл | размер | sha256 | проверяется скриптом |
|---|---|---|---|
| `docs/notes/rmx3630-lk/boot.img` | 67 108 864 | `8c9ef5391a6f90fa43bcf46cdd4eeb4bdbae9b55595b9bdb2e4d84c20d45a8c9` | да (иначе `build` отказывается) |
| `/tmp/fw/vendor_boot.img` | 67 108 864 | `1fa1e890275b176b85ef2c7186910d497f14f1642013a0a42c862b60977e7ab4` | да |

Обе — v4. boot: header 0x630, kernel 20 410 061, ramdisk 1 649 781 lz4-legacy
@0x1378000, встроенная vbmeta `AVB0` @0x150C000 (найдена по футеру `AVBf`,
а не по константе). vendor_boot: page 4096, ramdisk 35 835 345 lz4-legacy
@0x1000 (87 962 368 B cpio, 915 записей), dtb 191 577 @0x222E000, таблица
108 B/1 запись @0x225D000, `bootconfig_size = 0`, встроенная vbmeta
`AVB0` @0x225E000 (alg NONE, aux 384).

---

## 2. Что именно изменено

### 2.1 boot_v6.img

| что | было | стало |
|---|---|---|
| `/init` @файловый 0xF6D14 (VA 0x2F6D14) | `93 04 00 36` = `tbz w19,#0,0x2F6DA4` | `24 00 00 14` = `b 0x2F6DA4` (setenv безусловен внутри ветки `/force_debuggable`) |
| новый `/force_debuggable` | — | 0 B, mode 0100644 |
| новый `/adb_debug.prop` | — | 81 B, mode 0100644 |
| cpio | 14 записей | 16 записей |
| кодек рамдиска | lz4-legacy 1 649 781 | **gzip -9** 1 419 805 |
| header `.ramdisk_size` @0x0C | 0x192C75 | 0x15AA1D |
| всё остальное | — | побайтно сток |

`/adb_debug.prop` (ровно эти байты, sha256 `84bc904d…`):

```
ro.adb.secure=0
ro.debuggable=1
ro.force.debuggable=1
persist.sys.usb.config=adb
```

Чего **нет** (специально, по контракту): `/prop.default` не добавлен,
`system/etc/ramdisk/build.prop` не патчен, `/adb_keys` не добавлен.

Раскладка boot: kernel @0x1000 (байт-в-байт), рамдиск @0x1378000, конец
рамдиска 0x14D2A1D, vbmeta @0x150C000 → запас 234 979 B. Хвост
`[0x150C000 .. EOF)` скопирован из стока целиком (проверено `cmp`, exit 0).
Изменённые страницы: страница 0 (поле размера) и только страницы слота
рамдиска 0x1378..0x150A — больше ни одна 4-килобайтная страница не отличается
от стока.

### 2.2 vendor_boot_v6.img

| что | было | стало |
|---|---|---|
| `system/bin/init` @файловый 0xF1710 (PIE, VA==offset) | `33 05 00 36` = `tbz w19,#0,0xF17B4` | `29 00 00 14` = `b 0xF17B4` |
| новые `/force_debuggable`, `/adb_debug.prop` в корне cpio | — | те же 0 B / 81 B |
| `/init` (симлинк → `/system/bin/init`) | 0120750 | **не тронут** (mode и тело проверяются) |
| cpio | 915 записей | 917 записей |
| кодек | lz4-legacy 35 835 345 | lz4-legacy 36 602 570 |
| header `.vendor_ramdisk_size` @24 | 0x222CDD1 | 0x22E82CA |
| таблица entry[0] (size, offset, type, name, board) | 35 835 345 / 0 / 1 / "" / нули | 36 602 570 / 0 / 1 / "" / нули |
| layout | ramdisk@0x1000 dtb@0x222E000 table@0x225D000 vbmeta@0x225E000 | ramdisk@0x1000 **dtb@0x22EA000 table@0x2319000 vbmeta@0x231A000** |
| dtb (191 577 B) | sha256 `66d8b85d…` | тот же (байт-в-байт) |
| `bootconfig_size` | 0 | 0 |
| размер файла | 67 108 864 | 67 108 864 (== размер раздела) |

Итого в памяти LK: vendor 36 602 570 + boot 1 419 805 + 0x800 = 38 024 423 B
≤ 64 MiB (`LK_RAMDISK_SIZE`, проверка `cmp w3,#0x4000000` в `lk_payload`).
Запас ~29 MB.

### 2.3 Кодек: почему boot = gzip, vendor_boot = lz4-legacy

- Для boot честно измерено: наш pure-python LZ4-legacy компрессор даёт на этом
  рамдиске **1 857 958 B > 1 654 784 B** (слот до vbmeta) — образ был бы
  невалиден (перезапись vbmeta). gzip -9 даёт 1 419 805 B (запас 234 979 B),
  а gzip-рамдиск boot уже был прошит в v5 и загрузился
  (`CONFIG_RD_GZIP=y`, см. `re-vendor-boot-q1.md` §6.2). Поэтому boot — gzip.
- Для vendor_boot gzip недопустим по контракту → lz4-legacy обязателен.
  Реализован greedy-компрессор блока LZ4 (token/literals/offset/matchlen,
  последние 5 байт — литералы, последний матч не ближе 12 байт к концу).
  Legacy-фрейм: magic `0x184C2102` + блоки ≤ 8 MiB, каждый со своим u32-размером.
  Блоки стока, содержимое которых не менялось, **переиспользуются побайтно**
  (9 из 11); пересжимаются только блок с P2 и последний (12 465 236 B).
  Это валидно, т.к. блоки legacy-фрейма независимы (окно 64 KiB внутри блока).
- Кросс-проверка независимым инструментом: `lz4 -d -c` на нашем фрейме даёт
  87 962 708 B, sha256 `cd602d9f…` — **побайтно совпало** с нашим декодером.
  Плюс скрипт сам делает round-trip `compress → decompress == cpio` и
  отказывается писать образ при расхождении.

---

## 3. AVB: что можно и что нельзя починить

### 3.1 boot: хвост оставлен стоковым (подпись не воспроизводима)

Встроенная vbmeta boot подписана `SHA256_RSA2048` (ключ OPLUS sha1
`3c5f7b18…`), hash descriptor покрывает `[0, 0x150C000)`. Наш рамдиск меняет
дайджест → **AVB-верификация boot заведомо даст mismatch**. Это ровно ситуация
v5, которая на этом аппарате загружалась (unlocked, LK
`ALLOW_VERIFICATION_ERRORS`, `img_auth_required=0`; см. `re-adbd-apex-route.md`
§3.3). Скрипт не пытается «починить» подпись: `[vbmeta..EOF)` копируется
байт-в-байт.

### 3.2 vendor_boot: vbmeta unsigned → hash пересчитан

Стоковый vendor_boot-vbmeta: `algorithm = NONE`, auth-блок 0, aux 384, один
`AvbHashDescriptor` (partition `vendor_boot`, salt `bcbeb2da…`, digest
`abc233a8…` = sha256(salt ‖ image[0:36 036 608))). Подписи нет, поэтому
пересчёт не «ломает» ничего криптографического:

- hash descriptor: `image_size` → 36 806 656 (0x231A000) и digest →
  sha256(salt ‖ новые байты `[0, 0x231A000)`);
- AVB-футер в последних 64 B: `original_image_size` и `vbmeta_offset` →
  0x231A000 (размер vbmeta 640 и все прочие поля не менялись);
- сам vbmeta-блок (640 B) перенесён на новый page-aligned offset
  (`bootconfig_off`, `bootconfig_size = 0`).

Верификатор проверяет эту самосогласованность (image_size + digest + футер).

### 3.3 Риск (не заявляю, что безопасно)

**Патч vendor_boot может быть, а может и не быть терпим AVB/LK — это
проверяет отдельный агент.** Здесь гарантировано только структурное
соответствие (layout/таблица/футер/hash descriptor) и побайтность dtb. Не
проверено на устройстве: политика LK в отношении vendor_boot на этом
загрузчике, привязка digest к чему-либо вне образа (seccfg/oplus auth), а
также поведение `avb_slot_verify` при нашем vbmeta. Поэтому:

- если LK откажется грузить vendor_boot — телефон уйдёт в preloader/bootloop,
  лечится откатом stock `vendor_boot_a` (§5.3);
- по `re-vendor-boot-q1.md` §6-§7 патч vendor_boot для Q1 **не обязателен**
  (исполняется `/init` из boot-рамдиска); vendor_boot_v6 — страховка на случай
  обратного вердикта, а не «доказанно безопасный» шаг.

Дополнительно: 4-байтовые P1/P2 снимают только первое слагаемое гейта
`SecondStageMain` (`INIT_FORCE_DEBUGGABLE=="true"`), но **не** второе
(`fs_mgr::IsDeviceUnlocked()` ⇔ `verifiedbootstate=="orange"`, см.
`re-init-prop-gate.md` §3). Если LK рапортует не orange, `ro.adb.secure`
останется 1 даже с v6 — это ожидаемо и проверяется на устройстве
(`getprop ro.boot.verifiedbootstate`).

---

## 4. Верификатор (`verify`) — независимый разбор

`verify` **не** использует оффсеты/структуры билдера: у него свои парсеры
boot-заголовка (литеральные смещения v3/v4), v4 vendor_boot-заголовка,
AVB-футера, hash-дескриптора, cpio-walker и декодер ветки AArch64. Общими
являются только примитивы декодирования (`vendor_boot_extract.py`), что
требуется самим контрактом, и внешний вызов
`vendor_boot_extract.py --info/--list`.

Проверки (43, все PASS; exit 0 только если 0 FAIL):

```
PASS  boot: magic/header v4/header_size 0x630
PASS  boot: kernel_size unchanged [0x1376ECD]
PASS  boot: ramdisk offset = align(0x1000+kernel) [0x1378000]
PASS  boot: size field == real ramdisk bytes [ramdisk_size=1419805]
PASS  boot: kernel bytes byte-identical to stock
PASS  boot: header/vbmeta/EOF tail byte-identical to stock [vbmeta@0x150C000 ...]
PASS  boot: AVB0 at vbmeta offset, AVBf in last 64 B
PASS  boot: ramdisk end < vbmeta offset [end=0x14D2A1D < 0x150C000, slack=234979]
PASS  boot: no nonzero bytes outside header/kernel/ramdisk/vbmeta sections
PASS  boot: ramdisk decodes (gzip), cpio parses [3146836 B cpio, 16 entries]
PASS  boot: cpio entry count == stock + 2 [14 -> 16]
PASS  boot: cpio prefix is stock bytes except the 3 init bytes [diffs=0xf6e78,0xf6e79,0xf6e7b]
PASS  boot: /init is a regular file of 3143536 B
PASS  boot: P1 bytes at 0xF6D14 are 24000014
PASS  boot: P1 decodes to 'b 0xF6DA4' (VA 0x2F6DA4)
PASS  boot: /init differs from stock only in the 4-byte patch site [3 bytes]
PASS  boot: /force_debuggable present, empty, 0100644
PASS  boot: /adb_debug.prop content == expected 81 B
PASS  boot: every stock entry preserved (no /prop.default, build.prop intact)
PASS  vendor_boot: file size == 64 MiB and <= partition
PASS  vendor_boot: still v4/page 4096/one PLATFORM fragment
PASS  vendor_boot: kernel/tags/dtb addrs, cmdline and name unchanged
PASS  vendor_boot: header page identical except vendor_ramdisk_size@24
PASS  vendor_boot: ramdisk@0x1000, dtb/table/vbmeta page-aligned in order
PASS  vendor_boot: table entry points exactly at ramdisk, size == header size
PASS  vendor_boot: table type/name/board_id unchanged (PLATFORM, all-zero board)
PASS  vendor_boot: dtb bytes byte-identical to stock [sha256 66d8b85d...]
PASS  vendor_boot: gap between ramdisk and dtb is zero padding
PASS  vendor_boot: no nonzero bytes outside header/ramdisk/dtb/table/vbmeta
PASS  vendor_boot: embedded vbmeta is unsigned (alg NONE) and self-consistent
PASS  vendor_boot: AVB footer -> same vbmeta offset, size 640, partition end
PASS  vendor_boot: ramdisk decodes (lz4-legacy), cpio parses [87962708 B, 917 entries]
PASS  vendor_boot: cpio entry count == stock + 2 [915 -> 917]
PASS  vendor_boot: cpio prefix is stock bytes except the 3 init bytes
PASS  vendor_boot: /init is still the untouched symlink -> /system/bin/init
PASS  vendor_boot: P2 bytes at 0xF1710 are 29000014
PASS  vendor_boot: P2 decodes to 'b 0xF17B4'
PASS  vendor_boot: system/bin/init differs only in the 4-byte patch site [3 bytes]
PASS  vendor_boot: /force_debuggable + /adb_debug.prop at the cpio root [props=81 B]
PASS  vendor_boot: every stock entry preserved; only the 2 files added
PASS  vendor_boot_extract.py --info exits 0
PASS  vendor_boot_extract.py --list exits 0
PASS  vendor_boot_extract.py --list shows the 2 added entries and 917 entries
43 checks, 0 failed -> PASS
```

Негативный тест (порча 1 байта в копии): `cp` образов в `/tmp/v6/corrupt/`,
`boot_v6.img[0x1378040] ^= 0xFF` →

```
FAIL  boot: ramdisk decodes (error)  [Error -3 while decompressing data: invalid code ...]
34 checks, 1 failed -> FAIL   (exit 1)

$ # вторая порча: 1 байт в хвосте vbmeta (0x150C100), проверяется другой инвариант
FAIL  boot: header/vbmeta/EOF tail byte-identical to stock
43 checks, 1 failed -> FAIL   (exit 1)
```

Дополнительно, вне скрипта:

```
$ cmp -i 22069248:22069248 docs/notes/rmx3630-lk/boot.img /tmp/v6/boot_v6.img   # exit 0
$ cmp -n 20410061 -i 4096:4096     docs/notes/rmx3630-lk/boot.img /tmp/v6/boot_v6.img   # exit 0
$ lz4 -d -c frag0(v6) | sha256sum   # cd602d9f… == нашему декодеру
$ readelf -h <оба пропатченных init>  # ELF64, парсится
$ r2: 0x002f6d14  24000014  b 0x2f6da4      (boot /init, VA)
$ r2: 0x000f1710  29000014  b 0xf17b4       (vendor system/bin/init)
```

---

## 5. Прошивка (DA, preloader 22d9:0006)

Предусловия как в `termux-host-runbook.md`: Termux native (не proot), root,
`setenforce 0`, OTG; цель — в preloader `22d9:0006` (Vol+ & Vol− + кабель).
Цель: **не** подключать кабель при старте Android, если нужен DA.

### 5.1 Обёртка (рекомендуется: бэкап + readback + отказ без бэкапа)

```sh
cd ~/mtkclient
export OPLUS_PATCH_LEVEL=5 OPLUS_SKIP_SLA=0 OPLUS_SKIP_HWINFO=1 OPLUS_NO_DRAIN=1 \
       OPLUS_LEGACY_HOST=1 OPLUS_STORAGE=ufs OPLUS_HWINFO_LATE=1 OPLUS_SBC_PATCH=0 \
       OPLUS_WRITE_BYPASS=1 OPLUS_FLUSH=1

# 1) сначала всегда dry-run: печатает план и 43 PASS, устройство не трогает
python3 docs/notes/build_v6_dual.py flash --vid 0x22d9 --pid 0x0006

# 2) реальная запись (сначала полный бэкап boot_a и vendor_boot_a)
V6_FLASH_GO=1 python3 docs/notes/build_v6_dual.py flash --vid 0x22d9 --pid 0x0006
```

Обёртка пишет по одному разделу: полный readback раздела в
`/tmp/v6/stock_<part>_<ts>.img`, sha256, затем write, затем readback и
побайтное сравнение; при несовпадении — автоматический откат этого раздела.

### 5.2 «Голые» команды mtkclient (если обёртка недоступна)

```sh
cd ~/mtkclient
python3 mtk.py --vid 0x22d9 --pid 0x0006 w boot_a        /tmp/v6/boot_v6.img
python3 mtk.py --vid 0x22d9 --pid 0x0006 w vendor_boot_a /tmp/v6/vendor_boot_v6.img
```

Одна команда на оба раздела (файл-скрипт mtkclient):

```sh
printf 'w boot_a /tmp/v6/boot_v6.img\nw vendor_boot_a /tmp/v6/vendor_boot_v6.img\n' \
  > /tmp/v6/flash_v6.txt
python3 mtk.py --vid 0x22d9 --pid 0x0006 script /tmp/v6/flash_v6.txt
```

(обе команды — «голый» путь без автоматического бэкапа: сначала сделайте
бэкап вручную, §5.3, или пользуйтесь обёрткой §5.1).

### 5.3 Readback + md5 после записи

```sh
cd ~/mtkclient
python3 mtk.py --vid 0x22d9 --pid 0x0006 r boot_a        /tmp/v6/rb_boot_a.img
python3 mtk.py --vid 0x22d9 --pid 0x0006 r vendor_boot_a /tmp/v6/rb_vendor_boot_a.img

md5sum /tmp/v6/rb_boot_a.img        /tmp/v6/boot_v6.img
md5sum /tmp/v6/rb_vendor_boot_a.img /tmp/v6/vendor_boot_v6.img
```

Ожидаемо: размеры 67 108 864 и **совпадающие** md5 (раздел ровно 64 MiB,
образы тоже). Дополнительно (офлайн, по readback):

```sh
python3 docs/notes/build_v6_dual.py verify -o /tmp/v6/readback   # образы положить туда же
python3 docs/notes/vendor_boot_extract.py --list /tmp/v6/rb_vendor_boot_a.img | grep -E \
  'cpio entries|force_debuggable|adb_debug.prop'
```

### 5.4 Откат (стоковые копии)

```sh
cd ~/mtkclient
# a) копии, снятые обёрткой (точные имена печатаются при прошивке):
python3 mtk.py --vid 0x22d9 --pid 0x0006 w boot_a        /tmp/v6/stock_boot_a_<ts>.img
python3 mtk.py --vid 0x22d9 --pid 0x0006 w vendor_boot_a /tmp/v6/stock_vendor_boot_a_<ts>.img

# b) или исходные стоковые файлы (сверить sha256 перед записью!):
sha256sum docs/notes/rmx3630-lk/boot.img        # 8c9ef5391a6f90fa43bcf46cdd4eeb4bdbae9b55595b9bdb2e4d84c20d45a8c9
sha256sum /tmp/fw/vendor_boot.img               # 1fa1e890275b176b85ef2c7186910d497f14f1642013a0a42c862b60977e7ab4
python3 mtk.py --vid 0x22d9 --pid 0x0006 w boot_a        docs/notes/rmx3630-lk/boot.img
python3 mtk.py --vid 0x22d9 --pid 0x0006 w vendor_boot_a /tmp/fw/vendor_boot.img
```

При отсутствии DA: `fastboot flash boot_a boot.img` / `fastboot flash
vendor_boot_a vendor_boot.img` теми же стоками (загрузчик разблокирован).

### 5.5 Что мерить после загрузки (когда adb поднимется)

```sh
getprop ro.boot.verifiedbootstate      # orange -> гейт Q2 пройден; иначе причина найдена
getprop ro.adb.secure                  # цель 0
getprop ro.debuggable                  # цель 1
ls -l /init; sha256sum /init           # b8088eb2… = исполняется boot-рамдиск (Q1)
ls -l /force_debuggable /adb_debug.prop && cat /adb_debug.prop
```

Без adb: DA-readback обоих разделов + `build_v6_dual.py verify` по readback
(структурная проверка тем же независимым путём).

---

## 6. Файлы

| файл | назначение |
|---|---|
| `docs/notes/build_v6_dual.py` | `build` / `verify` / gated `flash`; stdlib + `vendor_boot_extract.py` |
| `docs/notes/reverse/re-v6-build.md` | этот отчёт |

Не менялись: `vendor_boot_extract.py`, `verify_adb_state.sh`,
`sparse_unpack.py`, `erofs_lite.py`, `re-lk-initrd-and-vbst.md`, все трекаемые
бинарники (`docs/notes/rmx3630-*/**`). Ничего не коммитилось; образы лежат
только в `/tmp/v6/`.

## 7. Ограничения / честные оговорки

1. Всё проверено **офлайн**. Ни одна проверка не подтверждает, что LK/AVB
   примет vendor_boot_v6 (это отдельная задача), и не подтверждает, что
   `ro.adb.secure` станет 0 (нужен `verifiedbootstate=="orange"`, §3.3).
2. `verify` проверяет структуру и содержимое, а не загрузку. «PASS» здесь =
   «образы собраны по контракту и самосогласованы», не «телефон загрузится».
3. Компрессор LZ4-legacy — свой (greedy), не эталонный `lz4 -l`; валидность
   подтверждена round-trip внутри сборки, независимым `lz4 -d` и тем, что
   ядро уже разбирает такой же legacy-фрейм у стока. Сжатие чуть хуже
   стокового на пересжимаемых блоках (36 602 570 vs 35 835 345 = +766 KB),
   но с большим запасом до 64 MiB.
4. Порядок байт/поля заголовков трактуются по `vendor_boot_extract.py` и
   `re-vendor-boot-q1.md`; расхождений при разборе стока не обнаружено.
