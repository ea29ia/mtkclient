# Q1: чей `/init` исполняется — из boot-рамдиска или из vendor_boot?

Дата: 2026-10-25. Устройство не подключено (proot, нет `/dev/bus/usb`) — всё ниже
получено из стоковой прошивки, без DA и без флеша.

Инструмент: `docs/notes/vendor_boot_extract.py` (pure-python cpio newc + pure-python
LZ4 legacy/frame, gzip через zlib).

---

## 0. Вердикт (TL;DR)

```
vendor_boot contains /init:  YES (16-byte symlink -> /system/bin/init, plus a real
                                  2 097 128-byte /system/bin/init)
executed /init comes from:   BOOT ramdisk  (3 143 536 B, sha256 b8088eb2…)
why:                         generic (boot) ramdisk is concatenated AFTER the vendor
                             ramdisk, so it is the overlay; for a type mismatch
                             (/init REG vs /init LNK) the kernel unlinks the old entry.
Q1 hypothesis is therefore:  FALSE — v5 не был перекрыт vendor_boot'ом.
```

Проверка на устройстве (1 минута, когда появится root): `ls -l /init` — регулярный
файл `-rwx---` = победил boot; симлинк `lrwxrwxrwx -> /system/bin/init` = победил
vendor_boot (тогда вердикт неверен, см. §8 plan B).

---

## 1. Артефакты и метод

Из `RMX3630export_11_14.0.0.200EX01_2024090223460108.zip` (9.5 GB, Zip64),
стримингом через `zipfile.open()` (архив целиком НЕ распаковывался), извлечены
только два члена:

| файл в zip | размер | sha256 |
|---|---|---|
| `IMAGES/boot.img` | 67 108 864 (0x4000000) | `8c9ef5391a6f90fa43bcf46cdd4eeb4bdbae9b55595b9bdb2e4d84c20d45a8c9` |
| `IMAGES/vendor_boot.img` | 67 108 864 (0x4000000) | `1fa1e890275b176b85ef2c7186910d497f14f1642013a0a42c862b60977e7ab4` |

`IMAGES/boot.img` **побайтно совпадает** с трекаемым `docs/notes/rmx3630-lk/boot.img`
(тот же sha256) — то есть локальный «сток boot_a» действительно сток.

`vendor_boot.img` с устройства не дампался ни разу; это первый его разбор.

---

## 2. vendor_boot.img: заголовок (header_version = 4)

| поле | значение |
|---|---|
| magic | `VNDRBOOT` |
| header_version | 4 |
| page_size | 4096 |
| kernel_addr | 0x40000000 |
| ramdisk_addr | **0x66F00000** |
| vendor_ramdisk_size | 35 835 345 (0x222CDD1) |
| cmdline | `bootopt=64S3,32N2,64N2 buildvariant=user` |
| tags_addr | 0x47C80000 |
| name | "" |
| header_size | 0x850 (2128) |
| dtb_size / dtb_addr | 191 577 (0x2EC59) / 0x47C80000 |
| vendor_ramdisk_table_size | 108 |
| vendor_ramdisk_table_entry_num | **1** |
| vendor_ramdisk_table_entry_size | 108 |
| bootconfig_size | **0 (секции bootconfig нет)** |
| layout | ramdisk @0x1000, dtb @0x222E000, table @0x225D000, bootconfig @0x225E000 |

Следствие: `androidboot.*` в этом образе **отсутствуют** — весь cmdline ядра
собирает LK (в `lk.img` есть литералы `androidboot.force_normal_boot=1`,
`androidboot.slot_suffix=%s`, `oplusboot.mode=…`). Ссылаться на bootconfig-ключи
как на аргумент нельзя — его тут физически нет.

---

## 3. Таблица фрагментов и кодек

| # | type | name | board_id | offset в образе | size | кодек |
|---|---|---|---|---|---|---|
| 0 | 1 = `VENDOR_RAMDISK_TYPE_PLATFORM` | "" | все 0 | 0x1000 | 35 835 345 | **lz4-legacy** (magic `02 21 4C 18`) |

`type=PLATFORM` + нулевой `board_id` = загрузчик обязан грузить этот фрагмент
всегда (AOSP: «VENDOR_RAMDISK_TYPE_PLATFORM ramdisks contain platform specific
bits. The bootloader must always load these into memory»).

Сжатый фрагмент: sha256 `5d949fd0b9a37a590c0f6a459f9a747237b5d97a5d54797426ffa13c1f2bed20`,
35 835 345 B → **87 962 368 B** cpio (sha256 `6fa98ce5743dbd7d2823870654a58a0b94c513406c1015b15a5193959e4f98b5`),
**915 записей** cpio newc.

Устройство: 1 фрагмент = весь `vendor_ramdisk_size`, без выравнивания между
фрагментами.

---

## 4. Что внутри vendor-рамдиска

```
$ python3 docs/notes/vendor_boot_extract.py --list /tmp/fw/vendor_boot.img
  cpio entries: 915
  INIT: init              size=16       sha256=bbbdc95750f115afc6e9739235885bb7f99141c57477f26261a565c5c547b9d9
  INIT: system/bin/init   size=2097128  sha256=de4092871407b7946fbe8c55e75577d12bdb836d911a8c279ae2490fd0d580cd
```

| путь | размер | mode | примечание |
|---|---|---|---|
| `/init` | 16 | 0120750 | **симлинк**, тело = `/system/bin/init` |
| `/system/bin/init` | 2 097 128 | 0100755 | реальный ELF aarch64 (ET_DYN) |
| `/force_debuggable` | — | — | **ОТСУТСТВУЕТ** |
| `/adb_debug.prop` | — | — | **ОТСУТСТВУЕТ** |
| `/debug_ramdisk` | 0 | 040755 | пустой каталог (есть) |
| `/first_stage_ramdisk/…` | — | — | `fstab.mt6789` 8221, `e2fsck` 239576, `snapuserd` 1009424, `system/bin/linker64` 1769008, `lib64/*` |
| `/prop.default` | 37 614 | | читается только в recovery |
| `/default.prop` | 12 | | симлинк → `prop.default` |
| `/system/build.prop` | 3 007 | | ramdisk-версия, не полный system |
| `/system/etc/init/hw/init.rc` | 11 486 | | плюс весь `/system/bin/*` (logcat, linker64, …) |

`/init` идёт в cpio **39-м**, `system/bin/init` — **497-м**. Оба ELF содержат
`INIT_FORCE_DEBUGGABLE`, `/force_debuggable`, `/userdebug_plat_sepolicy.cil`,
`/debug_ramdisk/adb_debug.prop` → оба умеют first stage, но это **разные сборки**:

| строка в бинаре | boot `/init` (3 143 536) | vendor `/system/bin/init` (2 097 128) |
|---|---|---|
| `Do not have permissions to set` | 0 | 1 |
| `property_set_fd` | 0 | 1 |
| `Starting service` | 0 | 1 |
| `Parsing ` / `init.rc` | 0 / 0 | 3 / 1 |
| ` second stage` | 0 | 2 |
| `selinux_setup` | 1 | 1 |

Т.е. boot-овский `/init` — сборка **только first stage** (нет property service и
парсера `init.rc`), а vendor-овский `system/bin/init` — полный init. Под вердиктом
§7 вторая стадия — это `/system/bin/init` из **system.img** (3 085 160 B), ровно
тот бинарь, который разбирали в Q2 (`/debug_ramdisk/adb_debug.prop` @0x156FE4).
Это независимая проверка на согласованность: Q1 и Q2 сходятся на одном и том же
втором стадии.

Вывод по составу: vendor-фрагмент — это 2SI-рамдиск OPLUS/MTK (симлинк `/init` →
`/system/bin/init` — классическая раскладка Android 9–10), а не «vendor-дополнение»
к GKI-рамдиску. Именно поэтому вопрос Q1 и возник.

---

## 5. boot.img: разбор (deliverable 2)

| параметр | значение |
|---|---|
| magic / header_version | `ANDROID!` / 4 |
| header_size | 0x630 |
| kernel_size @0x1000 | 20 410 061 (0x13777CD) |
| ramdisk_size @ **0x1378000** | 1 649 781 (0x192C75) |
| кодек рамдиска | **lz4-legacy** (`02 21 4C 18`), НЕ gzip |
| сжатый рамдиск sha256 | `414949ac6ebfdd052aa4a6dad0a96bba1a17fd22526f7d4ff7a8a25e7319efc9` |
| распакованный cpio | 3 146 496 B, sha256 `2b701091a8cf0c29a187e0440c3bbf6016e2809b0ef396b71831f2d1c030a135` |
| записей cpio | 14: `debug_ramdisk/ dev/ init lib/ lib/modules metadata/ mnt/ proc/ second_stage_resources/ sys/ system/ system/etc/ system/etc/ramdisk/ system/etc/ramdisk/build.prop(877)` |
| `/init` | 3 143 536 B, mode 0100750, sha256 `b8088eb2b895da034ba6048a159068b5ca6f39b54d40a849e66ec33a12b907c6` |
| `/force_debuggable` | **ОТСУТСТВУЕТ** (в стоке) |
| `/adb_debug.prop` | **ОТСУТСТВУЕТ** (в стоке) |
| встроенная vbmeta | `AVB0` @ **0x150C000** (22 069 248), vbmeta 1.0, auth=0x140, aux=0x400, alg=1 |
| AVB-футер | `AVBf` в последних 64 байтах |

Бюджет рамдиска: `0x150C000 - 0x1378000 = 0x194000 = 1 654 784` B. Сток занимает
1 649 781 → свободно всего **5 003 байта**. Цифра `0x194000` из handoff'а верна,
а вот адрес vbmeta — нет: она на `0x150C000`, не на `0x1513000`
(`0x1513000` внутри образа — нули, см. §10).

Патч-сайт v5 в стоковом `/init`: `VA 0x2F6D14` = файловый offset **0xF6D14**,
байты `93 04 00 36` (`tbz w19,#0,0x2F6DA4`) — подтверждено, сток непатчен.

---

## 6. Доказательства того, чей `/init` побеждает

### 6.1 Спецификация AOSP (обязательное требование к загрузчику)

> «The bootloader must load the generic ramdisk into memory immediately following
> the vendor ramdisk (the CPIO, Gzip, and lz4 formats support this type of
> concatenation). Don't page align the generic ramdisk image or introduce any
> other space between it and the end of the vendor ramdisk in memory. After the
> kernel decompresses, it extracts the concatenated file into an initramfs, which
> results in a file structure that's a **generic ramdisk overlaid on the vendor
> ramdisk** file structure.»
>
> «The bootloader can decide the order to load the selected vendor ramdisks, as
> long as the **generic ramdisk is loaded last**.»
>
> — source.android.com/docs/core/architecture/partitions/vendor-boot-partitions

Порядок в памяти: `[vendor ramdisk @0x66F00000][generic (boot) ramdisk]`.
Overlay = generic поверх vendor → при совпадении путей выигрывает boot.

### 6.2 Ядро 5.10.198-android12 (init/initramfs.c)

Устройство: `Linux version 5.10.198-android12-9-o-gf7a7af5fc933`, в `ikconfig`:
`CONFIG_RD_GZIP=y`, `CONFIG_RD_LZ4=y`, `CONFIG_RD_ZSTD=y` — оба кодека допустимы.

Разбор дубликатов (v5.10, `init/initramfs.c`):

```c
static void __init clean_path(char *path, umode_t fmode)
{
        struct kstat st;
        if (!init_stat(path, &st, AT_SYMLINK_NOFOLLOW) &&
            (st.mode ^ fmode) & S_IFMT) {
                if (S_ISDIR(st.mode)) init_rmdir(path);
                else                   init_unlink(path);
        }
}
...
static int __init do_symlink(void)
{
        clean_path(collected, 0);          /* fmode=0 -> unlink любого типа */
        init_symlink(...);
}
static int __init do_name(void)           /* regular file */
{
        clean_path(collected, mode);       /* S_IFREG vs S_IFLNK -> unlink */
        ... filp_open(collected, O_WRONLY|O_CREAT|O_TRUNC, mode);
}
```

То есть при распаковке `[vendor cpio][boot cpio]`:

1. vendor создаёт `/init` — симлинк на `/system/bin/init`;
2. vendor создаёт `/system/bin/init` (2 097 128 B);
3. boot приносит `/init` как **regular file** → `clean_path("init", S_IFREG)` видит
   `S_IFLNK ≠ S_IFREG` → `init_unlink("/init")` → создаётся обычный файл 3 143 536 B.

Итог: `/init` = бинарь из boot-рамдиска. Симлинк vendor'а не «перекрывает» его ни
при каком порядке — тип не совпадает, и проигрывает тот, кто распакован раньше.

### 6.3 LK (локальный `docs/notes/rmx3630-lk/lk.img`, MT6789)

`lk.img` = MTK-заголовок (0x200) + raw aarch64 payload (`lk_payload.bin`, 935 424 B).
В `boot_linux_from_storage` (inlined `boot_linux_fdt`) считается пара
`linux,initrd-start/end`:

```
d5e4  mov  x8, #0x66f00000          ; == vendor_boot header .ramdisk_addr
d5ec  add  x1, x8, w27, uxtw        ; x1 = 0x66F00000 + w27 (весь initrd)
d5f4  bl   0xb46c                   ; (fdt, addr) -> дописать bootconfig, вернуть его размер
...
d5fc  add  w9, w22, w27             ; w9 = initrd_start + w27
d600  add  w9, w9, w0               ;    + bootconfig_size
d604  fdt setprop "linux,initrd-end" (0x9208f) = bswap32(w9)
d574  fdt setprop "linux,initrd-start" (0x92073) = bswap32(x26)
```

Что это доказывает: `linux,initrd-start` = `0x66F00000` (адрес **vendor**-рамдиска),
`end` = `start + w27 + bootconfig`, а bootconfig пишется ровно в
`0x66F00000 + w27`. Linux ищет `#BOOTCONFIG` в **хвосте initrd**, значит
`0x66F00000 + w27` — конец всего блоба, т.е. `w27 = vendor_ramdisk_size +
generic_ramdisk_size`, а generic лежит **после** vendor. Обратный порядок
(`[generic][vendor]`) дал бы bootconfig в середине чужого блока — заведомо
нерабочая раскладка.

Плюс проверки в том же файле: блок рамдиска резервируется ровно по `0x66F00000`
(`cmp x0, #0x66f00000` → иначе «mb_ramdisk»-ошибка), размер округляется до 2 MiB,
и есть жёсткий лимит `LK_RAMDISK_SIZE` с запасом 0x800 под bootconfig:

```
db58  add w3, w21, #0x800           ; w21 = суммарный размер initrd
db60  cmp w3, #0x4000000            ; 64 MiB
db78  ...  "ramdisk_map_sz (0x%x) cannot overrun LK_RAMDISK_SIZE (0x%x)"
```

Т.е. общий блоб начинается по адресу vendor-рамдиска и растёт вверх: сначала
vendor (он уже лежит по 0x66F00000), затем generic. Это ровно порядок из §6.1,
а не обратный.

### 6.4 Что НЕ является доказательством

* `bootconfig_size = 0` — ключей `androidboot.*` в vendor_boot нет, cmdline только
  `bootopt=64S3,32N2,64N2 buildvariant=user`;
* `vendor_ramdisk_size` (35.8 MB) и наличие `/system/bin/init` сами по себе ничего
  не решают — решает порядок склейки;
* наблюдение «v5 не сработал» **не** различает гипотезы: под Q2 (вторая стадия
  отбрасывает `ro.adb.secure` из `/debug_ramdisk/adb_debug.prop`) unauthorized
  объясняется и без Q1.

---

## 7. Ответ на Q1

**vendor_boot содержит `/init` — да** (симлинк 16 B → `/system/bin/init`, плюс сам
`/system/bin/init` 2 097 128 B, sha256 `de4092…`). Но **исполняется не он**:
generic-рамдиск из `boot.img` грузится последним и является overlay'ем, а при
несовпадении типа (`REG` vs `LNK`) ядро удаляет старую запись (`clean_path`).
PID 1 = `/init` из boot-рамдиска, 3 143 536 B, sha256 `b8088eb2…` — сборка
first-stage-only, которая после `mount /system` делает
`execv("/system/bin/init")` уже из system.img (3 085 160 B).
`force_debuggable` и `adb_debug.prop` в vendor_boot отсутствуют, поэтому даже при
обратном порядке они бы не помогли без правки вендорного рамдиска.

Значит **Q1 не объясняет провал v5**; v5-патч `0xF6D14` попадает в исполняемый
бинарь. Дальше смотреть Q2 (гейт загрузки свойств во второй стадии).

---

## 8. План v6

### Plan A (рекомендуемый, по доказательствам): правим только boot.img

Ничего в vendor_boot не трогаем — пересборка 88 MB lz4-фрагмента с пересчётом
таблицы/смещений dtb+bootconfig даёт риск, но нулевой выигрыш.

1. Источник: сток `IMAGES/boot.img` (sha `8c9ef539…`), **не** v5-образ.
2. Рамдиск:
   * `/init` — 4 байта по offset **0xF6D14**: `93 04 00 36` → `24 00 00 14`;
   * оставить `/force_debuggable` (0 B, mode 0644) — триггер копирования;
   * оставить `/adb_debug.prop` (`ro.adb.secure=0`, `ro.debuggable=1`,
     `ro.force.debuggable=1`, `persist.sys.usb.config=adb`);
   * добавить маркер `/v6_marker` (одна строка, 0 риска) — чтобы на устройстве
     одной командой отличить «boot-рамдиск распакован» от «нет»;
   * `/adb_keys` с хост-ключом — оставить.
3. Упаковка: **lz4-legacy** (кодек стока — убирает ещё одну переменную) или
   gzip -9 (ядро `CONFIG_RD_GZIP=y`); жёсткое требование — **≤ 1 654 784 B
   (0x194000)**, т.к. vbmeta на 0x150C000.
   v5 укладывался: 1 420 624 B (0x15AD50), запас 234 160 B.
4. Сборка: `python3 docs/notes/build_boot_gzip.py <сток boot.img> <out.img>`
   (скрипт сам находит `AVB0` после рамдиска и копирует хвост побайтно; в его
   докстринге адрес 0x1513000 устарел, код работает от фактического `AVB0`).
5. Проверка перед флешем:
   * `--info`-подобная проверка: kernel_size не изменился, `rd_off == 0x1378000`,
     `ramdisk_size ≤ 0x194000`, `AVB0` на месте 0x150C000, `AVBf` в конце;
   * `sha256` всего хвоста `[0x150C000, 0x4000000)` == сток.

### Plan B (страховка, только если §8-verification покажет симлинк `/init`)

Патчить **vendor_boot.img**, фрагмент 0 (единственный, type=PLATFORM):

* в распакованном cpio (`frag0.cpio`) файл `system/bin/init` начинается с
  `data_off = 0x30A5F74`; целевой байт-офсет в cpio — **0x3197684**
  (= `data_off + 0xF1710`), в самом ELF — offset **0xF1710**:
  `33 05 00 36` (`tbz w19,#0,0xF17B4`) → `29 00 00 14` (`b 0xF17B4`, на `setenv`);
  это точный аналог boot-патча `0x2F6D14→0x2F6DA4` (тот же код, сдвиг 0x74);
* добавить в cpio `/force_debuggable` и `/adb_debug.prop` (те же, что в boot);
* пересобрать фрагмент `lz4 -l` (legacy!), обновить
  `header.vendor_ramdisk_size` и `table[0].ramdisk_size`;
* пересчитать page-aligned смещения: dtb = 0x1000+align(new_size),
  table = dtb+align(191577), bootconfig = table+align(108); всё в пределах
  64 MiB (`0x4000000`) — сейчас занято 0x225E000, запас ~27 MiB;
* проверить: `--info` нового образа даёт тот же layout-порядок и
  `vendor_ramdisk_size` = сумме фрагментов, `--list` парсит ≥ 917 записей,
  sha256 нового `system/bin/init` = ожидаемый.

Порядок применения: сначала Plan A (дешево и по evidence), Plan B — только как
эксперимент, если подтвердится, что `/init` на устройстве — симлинк.

### Что проверить после прошивки (когда adb поднимется)

```
adb shell ls -l /init                 # -rwx--- = boot, lrwxrwxrwx = vendor
adb shell sha256sum /init             # b8088eb2… (boot) / de409287… (vendor)
adb shell sha256sum /system/bin/init  # 3 085 160 B = из system.img, не из рамдиска
adb shell cat /proc/cmdline           # androidboot.force_normal_boot=1
adb shell getprop ro.adb.secure       # цель 0
adb shell getprop ro.debuggable       # цель 1
```
Без adb: DA-readback `boot_a` и сравнение sha256 с собранным образом; наличие
`/v6_marker` проверяется там же (readback рамдиска + cpio-листинг).

---

## 9. Правки к предыдущим документам

| где | было | факт |
|---|---|---|
| HANDOFF §2.1, build_boot_gzip.py docstring | vbmeta на `0x1513000` | **`0x150C000`** (там `AVB0`; `0x1513000` — нули) |
| HANDOFF §2.1 | рамдиск на `0x137F000` | **`0x1378000`** (kernel 0x13777CD, page-align) |
| HANDOFF §2.1 / STATUS §19 | сток-рамдиск «gzip» | сток — **lz4-legacy**; gzip был только у наших сборок |
| PLAN §A | «в vendor_boot может быть init, он перекрывает» | init есть, но **не перекрывает** (overlay порядок) |
| — | — | `bootconfig_size = 0`, ключей `androidboot.*` в образе нет |

Свободное место: слот `0x194000` (1 654 784 B) — корректно, но не из-за
0x1513000, а из-за `0x150C000`; после сток-рамдиска остаётся 5 003 B.

---

## 10. Воспроизведение

```
python3 docs/notes/vendor_boot_extract.py --info    /tmp/fw/vendor_boot.img
python3 docs/notes/vendor_boot_extract.py --list    /tmp/fw/vendor_boot.img
python3 docs/notes/vendor_boot_extract.py --extract /tmp/fw/vb_out /tmp/fw/vendor_boot.img
python3 docs/notes/vendor_boot_extract.py --extract /tmp/fw/vb_unpack /tmp/fw/vendor_boot.img --unpack
```

Распаковка `--unpack` даёт дерево `frag0-root/` (915 записей, 88 MB), где
`frag0-root/init` — симлинк, а `frag0-root/system/bin/init` — реальный файл.

Хэши «каждого init» (boot-рамдиск распаковывается тем же парсером):

```
python3 - <<'PY'
import struct, sys; sys.path.insert(0,'docs/notes')
from vendor_boot_extract import cpio_newc_parse, detect_codec, decompress
d=open('/tmp/fw/boot.img','rb').read(); ks,rs=struct.unpack_from('<2I',d,8)
roff=4096+((ks+4095)//4096)*4096
raw,_=decompress(d[roff:roff+rs], detect_codec(d[roff:roff+rs]))
for e in cpio_newc_parse(raw):
    if e.name.lstrip('./')=='init': open('/tmp/fw/init_boot','wb').write(raw[e.data_off:e.data_off+e.size])
PY
sha256sum /tmp/fw/init_boot /tmp/fw/vb_unpack/frag0-root/system/bin/init
```

Валидация самописного LZ4: вывод pure-python декодера побайтно совпадает с
референсным `lz4 -d -c` (sha256 `6fa98ce5…` для обоих, см. §3).
