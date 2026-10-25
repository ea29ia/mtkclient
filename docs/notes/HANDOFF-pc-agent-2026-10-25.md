# HANDOFF → агенту на ПК: RMX3630, adb unauthorized → v7

Дата: 2026-10-25. Ветка: `oplus-mt6789-unlock` (форк `ea29ia/mtkclient`).
Хост: ПК с подключённым RMX3630 (dead screen), артефакты в `/home/musin`.
Твоя задача: **собрать v7 из актуального `boot_a`, прошить только `boot_a`, проверить adb.**
Ты — единственный, у кого есть USB к телефону. Никаких «а вдруг» — всё ниже проверено офлайн.

---

## 0. TL;DR — что делать (6 шагов)

```sh
# 1) синхронизировать репо
cd ~/mtkclient && git fetch origin && git checkout oplus-mt6789-unlock && git pull --ff-only

# 2) снять ТЕКУЩИЙ boot_a (preloader: питание off, Vol Up + Vol Down + Power + кабель → 22d9:0006)
python3 mtk.py r boot_a /home/musin/boot_a_now.img
md5sum /home/musin/boot_a_now.img          # ожидание: f0c1674243f465d9bb363a45642d2117 (v5)

# 3) собрать v7 из ЭТОГО дампа (спека §4, скрипт — твой)
python3 tools/build_v7_from_dump.py /home/musin/boot_a_now.img /home/musin/boot_v7.img
python3 tools/build_v7_from_dump.py --verify /home/musin/boot_a_now.img /home/musin/boot_v7.img

# 4) прошить (обёртка сама делает полный бэкап + readback + авто-откат)
cp /home/musin/boot_v7.img /home/musin/boot_patched.img
FLASH_GO=1 ./run_flash_boot_patched.sh        # dry-run: тот же вызов без FLASH_GO

# 5) ритуал включения (иначе preloader ждёт DA)
#    выдернуть кабель → Power ~10 с (off) → Power ~3 с → 90 с БЕЗ кабеля → вставить кабель

# 6) проверка
adb devices                       # цель: serial БЕЗ "unauthorized"
adb shell getprop ro.adb.secure   # цель: 0
adb shell id                      # цель: uid=0(root)
```

Если на шаге 6 снова `unauthorized` — **не перебирать варианты рамдиска**, идти в §6 (дерево решений).

---

## 1. Где мы сейчас (факты)

| факт | значение | откуда |
|---|---|---|
| Android загружается | да, USB `22d9:2769`, ADB интерфейс `ff/42/01` | handoff §1 |
| adb | `unauthorized` | то же |
| boot_a | v5 (патченый рамдиск) | md5 `f0c16742…` |
| seccfg | `lock_state=3`, RPMB-зеркало `locked=0` | handoff §1 |
| экран | мёртвый (шелл/логи недоступны) | — |
| DA/preloader | `22d9:0006`, только при выключенном телефоне | runbook |

`ro.adb.secure=1` — **не измерение**, а вывод из `/system/build.prop`; единственный рантайм-факт — `unauthorized`.

---

## 2. Почему v5 не сработал (дизасм, не гипотеза)

Цепочка: LK → kernel+initrd → `/init` (first stage, 3 143 536 B) → `execv("/system/bin/init","second_stage")` → `PropertyInit()` → adbd.

Гейт во **второй** стадии (`/system/bin/init`, 3 085 160 B, `sha256 a458669b…`):

```asm
0x1344ac  bl getenv("INIT_FORCE_DEBUGGABLE")
0x1344b0  cbz x0, 0x13453c                     ; нет env → без debug props
0x1344b8  bl AvbHandle::IsDeviceUnlocked()     ; == (verifiedbootstate == "orange")
0x1344bc  tbz w0,#0, 0x13453c                  ; не orange → та же ветка
0x134548  bl UmountDebugRamdisk()              ; ← umount("/debug_ramdisk")
0x13454c  bl PropertyInit()                    ; ← только теперь читаются свойства
```

`UmountDebugRamdisk` (`0x139A00`) = `umount()` и лог (`0x139A28`), **без** `rmdir`/удаления.
`PropertyLoadBootDefaults` читает `access("/debug_ramdisk/adb_debug.prop", R_OK)` (`0x156FF0`).

Следствие: если гейт не прошёл, tmpfs с копией `/adb_debug.prop` снимается **до** чтения свойств,
файла нет → грузится `ro.adb.secure=1` из `/system/build.prop` → `unauthorized`.
Патч `0x2F6D14` (v5, `tbz → b`) корректен и снимает только **первое** условие гейта.

Почему остальные попытки мимо: `/prop.default` читается только в recovery; `/adb_keys` в рамдиске
получает `rootfs:s0` и adbd его не примет (нужен `/data/misc/adb/adb_keys`, `adb_keys_file`);
`system/etc/ramdisk/build.prop` грузится раньше `/system/build.prop` и перетирается.

Полные разборы: `docs/notes/reverse/re-init-prop-gate.md`, `re-lk-initrd-and-vbst.md`.

---

## 3. Идея v7 (одна правка, без LK/seccfg/vendor_boot)

`/debug_ramdisk` — это **каталог в cpio**, поверх которого монтируется tmpfs. Значит файл можно
положить **внутрь каталога**: пока tmpfs смонтирован, он невидим; после `umount` — виден.
Тогда `access()` находит свойства в **обеих** ветках гейта.

```
cpio rootfs:  debug_ramdisk/adb_debug.prop   (наш файл, 81 B)
first stage:  mount tmpfs /debug_ramdisk;  copy /adb_debug.prop -> /debug_ramdisk/adb_debug.prop
second stage: гейт прошёл  -> видна копия в tmpfs        -> свойства грузятся
              гейт упал    -> umount -> виден наш файл   -> свойства грузятся
```

Содержимое (81 B, ровно так, `\n` в конце каждого):

```
ro.adb.secure=0
ro.debuggable=1
ro.force.debuggable=1
persist.sys.usb.config=adb
```

`ro.*` write-once не мешает: init собирает все boot-файлы в один `std::map` (поздние перекрывают
ранние, `adb_debug.prop` — последний) и применяет один раз.

**Поэтому `verifiedbootstate` больше не важен.** Не трогаем ни LK, ни seccfg, ни RPMB.

Что НЕ надо делать (доказано): править `vendor_boot` (его `/init` — симлинк, перекрывается
boot-рамдиском; LK склеивает `vendor‖boot`, `memcpy` `0x5000DDB8`/`0x5000DDFC`); патчить adbd в APEX
(подпись Google, `sha1 d0b0b877…`); пересобирать `system_a` (EROFS + `vbmeta_system` под ключом OPLUS);
класть `/init2` (SELinux: `entrypoint` только на `init_exec`, `relabelto` запрещён).

---

## 4. ВАЖНО: собирать ТОЛЬКО из актуального boot_a

`docs/notes/rmx3630-lk/boot.img` (== `IMAGES/boot.img` из прошивки) — **другая, старая сборка**:

| | старый дамп/прошивка | реальный `boot_a` сейчас |
|---|---|---|
| `kernel_size` | `0x1376ECD` | **`0x137DD75`** |
| ramdisk offset | `0x1378000` | **`0x137F000`** |
| встроенная vbmeta | `0x150C000` | **`0x1513000`** |
| md5 | `10f3576a…` | `356320597c88669f032e9736e5f906ce` (сток) / `f0c16742…` (v5) |

Правило кампании (STATUS §15): **никогда не собирать образ для прошивки из файлов прошивки/старых
дампов** — только из свежего бэкапа этой же сессии.

Образ, собранный мной здесь (`/tmp/v7/boot_v7.img`, sha256 `bd0d5dc7…b9466`, 47/47 инвариантов) —
**эталон преобразования, НЕ для прошивки** (он на старом ядре). Тебе нужно воспроизвести ту же
трансформацию на реальном дампе.

### Спека сборки (v5-дамп → v7)

Вход `D` — 64 MiB образ, `ANDROID!`, header v4:

1. `kernel_size = u32@0x08`, `ramdisk_size = u32@0x0C`, `header_size = u32@0x14`, `hdr_version = u32@0x28`.
2. `rd_off = align_up(0x1000 + kernel_size, 0x1000)`; проверить кодек по сигнатуре:
   `1f 8b` → gzip, `02 21 4c 18` → LZ4-legacy (у v5 — gzip).
3. распаковать → cpio `newc`; убедиться, что есть записи `debug_ramdisk` (dir `040755`)
   и `adb_debug.prop` (файл). Если чего-то нет — **STOP**, сообщить (значит дамп не v5).
4. добавить одну запись `debug_ramdisk/adb_debug.prop`, mode `0100644`, uid/gid 0, nlink 1, mtime 0,
   данные — **побайтно те же**, что у существующего `adb_debug.prop` (81 B). Больше ничего не менять;
   `/init` **не** патчить (в v5 он уже `24 00 00 14` по `0xF6D14`).
5. пересобрать cpio, сжать gzip `-9`, `mtime=0`.
6. найти `vbmeta_off` — первая страница с `AVB0` начиная от `rd_off`, выровненная на `0x1000`;
   для реального образа ожидается `0x1513000`, `slot = vbmeta_off - rd_off = 0x194000`.
   Проверить: `rd_off + len(gz) < vbmeta_off` (запас ~235 КБ).
7. новый образ: `header` (обновить только `ramdisk_size@0x0C`) + `D[0x1000:rd_off]` (ядро, байт-в-байт)
   + `gz` + нули до `vbmeta_off` + `D[vbmeta_off:]` **байт-в-байт** (vbmeta + футер). Размер 64 MiB.

Обязательные инварианты (`--verify`):

- `/init` sha256 и все сток-записи cpio не изменились; добавлена ровно одна;
- новый файл == существующему `adb_debug.prop` побайтно;
- `len(gz) <= slot`, `rd_off + len(gz) < vbmeta_off`;
- `[vbmeta_off..EOF]` и область ядра — байт-в-байт как в дампе;
- размер == 67 108 864;
- печатать: stock md5/sha256, kernel_size, ramdisk_size, rd_off, vbmeta_off, slot, размер/sha256/md5 выхода.

Референсная реализация примитивов (cpio/gzip/разметка/проверки) — `docs/notes/build_v6_dual.py`
(функции `build`/`verify`) и `docs/notes/boot_ramdisk_patch.py`. Учти: `build_v6_dual.py` сейчас
жёстко проверяет sha256 стока (старый образ) и `vbmeta @0x150C000` — либо добавь
`--allow-foreign-stock` + динамический поиск `AVB0`, либо пиши отдельный скрипт по спеке выше.
Готовый `/home/musin/boot_v7.img` должен проходить твой `--verify` целиком.

---

## 5. Прошивка и проверка

Обёртка `run_flash_boot_patched.sh` (`docs/notes/flash_boot_patched.py`) читает
`/home/musin/boot_patched.img`, поэтому копируем туда v7. Она делает: полный бэкап `boot_a` (64 МБ)
→ запись → readback + md5 → при расхождении автоматический откат. Требует `FLASH_GO=1`.

```sh
cp /home/musin/boot_v7.img /home/musin/boot_patched.img
FLASH_GO=1 ./run_flash_boot_patched.sh
```

Нюансы:

- preloader-режим: телефон **выключен**, `Vol Up + Vol Down + Power` + кабель → `22d9:0006`; `OPLUS_PATCH_F804_STUB` не включать;
- после записи телефон **не перезагружается** — ритуал из TL;DR (10 с / 3 с / 90 с без кабеля);
- откат: `BOOT_RESTORE=<бэкап из лога> FLASH_GO=1 ./run_flash_boot_patched.sh`.

После загрузки:

```sh
adb devices                          # serial, без unauthorized
adb shell getprop ro.adb.secure      # 0
adb shell getprop ro.debuggable      # 1
adb shell id                         # uid=0(root)   → дальше scrcpy
adb shell cat /proc/cmdline          # бонус: видно androidboot.verifiedbootstate
```

Если `ro.adb.secure` = 0, но `id` не root — это уже успех по adb; root добьёшь `adbd`-флагом позже.

---

## 6. Если снова `unauthorized` — дерево решений (не перебирать образы!)

1. **Проба LK (30 секунд, без шелла):**
   войти в fastboot (комбо из `docs/notes/re-lk-rescue-surfaces.md`), затем

   ```sh
   fastboot getvar all 2>&1 | tee /tmp/getvar_all.txt
   python3 docs/notes/lk_state_probe.py --decode /tmp/getvar_all.txt
   ```

   `getvar` разрешён и на залоченном устройстве. Смысл: `secure: no ⇔ lock_state==3 ⇔ orange`,
   это **один и тот же байт** (`0x50053ACC/0x50053AD4`), а не прокси.
   Переменных `avb`/`verifiedbootstate`/`lock_state` в этом LK **нет** (проверено по таблице команд).

2. **`secure: yes`** → LK считает устройство залоченным, т.е. запись seccfg не проходит валидацию
   (fail-safe в green). Тогда:
   `python3 mtk.py r seccfg /home/musin/seccfg_now.bin` (preloader) и
   `python3 docs/notes/seccfg_validate.py --info /home/musin/seccfg_now.bin`.
   Дальше чинится seccfg/RPMB, а не рамдиск. **Сначала бэкап** (сток seccfg md5 `12a94a3f…`).

3. **`secure: no`, а adb всё равно `unauthorized`** → гейт пройден, но файл не читается:
   снять `adb` нечем, поэтому верни мне: `getvar all`, md5 записанного образа, readback-лог.
   Гипотеза для проверки: первый stage не наш (тогда `ls -l /init` недоступен — но проверим
   косвенно, что дамп был именно v5).

4. **Пятисекундный stall НЕ использовать как доказательство orange** — `mdelay(0x4C4B40)` стоит только
   в ветке `state==2`, но выполняется и на стоковом boot, поэтому без green-базелайна ничего не значит.

---

## 7. Безопасность / запреты

- **Никогда** `WRITE-FLASH` (`w`/`wo`/`wf`) по `seccfg` — anti-tamper зануляет область.
- `seccfg`/RPMB — только с бэкапом: сток `seccfg` md5 `12a94a3ffbfc1a7f344e1dd6837b359a`,
  зеркало locked=1 `2374972dbf75743b4502861d22d84875`.
- Не стирать `metadata`/`userdata` (уже стёрты, повтор ничего не даёт).
- Не шить `vendor_boot` (бесполезно + лишний риск), не шить `system`/`vbmeta`.
- Все записи — только `*_GO=1` и только после readback.
- Не собирать образ из `docs/notes/rmx3630-lk/boot.img` / `IMAGES/boot.img`.

---

## 8. Артефакты и хэши

| файл | что | контроль |
|---|---|---|
| `/home/musin/boot_a_now.img` | снимаешь ты (ожидается v5) | md5 `f0c1674243f465d9bb363a45642d2117` |
| `/home/musin/boot_v7.img` | собираешь ты из дампа | свой sha256/md5 в отчёте |
| `/home/musin/boot_a_backup_*.img` | авто-бэкап обёртки | md5 из лога |
| `docs/notes/rmx3630-lk/boot.img` | **старая** сборка (не для шитья) | sha256 `8c9ef539…`, md5 `10f3576a…` |
| `/tmp/v7/boot_v7.img` (у меня) | эталон трансформации | `bd0d5dc7…`, 47/47 PASS |
| `/home/musin/boot_a_backup_20261024_225408.img` | реальный сток (если цел) | md5 `356320597c…` |

Собрать **из стока** тоже допустимо, но тогда к v7 добавляется весь дельта v5: P1 (`0xF6D14`:
`93 04 00 36 → 24 00 00 14`), `/force_debuggable`, `/adb_debug.prop`, `/adb_keys`, и **плюс** запись
`debug_ramdisk/adb_debug.prop`. Дампный путь короче и сохраняет ровно то ядро, что сейчас грузится.

---

## 9. Доки (что где лежит)

| файл | ответ |
|---|---|
| `reverse/re-vendor-boot-q1.md` | Q1: vendor_boot содержит `/init`-симлинк, но побеждает boot `/init` |
| `reverse/re-init-prop-gate.md` | Q2: гейт `env && IsDeviceUnlocked()`, `UmountDebugRamdisk` до `PropertyInit` |
| `reverse/re-adbd-apex-route.md` | Q3: APEX-путь закрыт (ключ Google), system — пересборка под OPLUS-ключ |
| `reverse/re-lk-initrd-and-vbst.md` | LK: порядок склейки initrd, `lock==3→orange`, `img_auth_required` |
| `reverse/re-init2-escape.md` | почему `/init2` невозможен (SELinux) + найден R4c (это и есть v7) |
| `reverse/re-v7-rootfs-prop.md` | v7: что и почему, инварианты, ожидаемый результат |
| `reverse/re-v6-build.md` | сборка/верификация boot+vendor_boot, **только для старой базы** |
| `reverse/re-lk-state-probe.md` | дерево решений `getvar secure` / seccfg |
| `reverse/re-adb-unauthorized-checklist.md` | 9 шагов диагностики `unauthorized` |
| `PLAN-q1-q2-2026-10-25.md` | контракты задач и рамки |
| `vendor_boot_extract.py`, `sparse_unpack.py`, `erofs_lite.py` | разбор образов |
| `lk_state_probe.py`, `seccfg_validate.py` | проба состояния LK и офлайн-валидация seccfg |
| `verify_adb_state.sh` | post-flash харнесс (dry-run по умолчанию) |

---

## 10. Что прислать назад (для приёмки)

```
STOCK_DUMP_MD5=
STOCK_DUMP_SHA256=
KERNEL_SIZE=
RD_OFF=
VBMETA_OFF=
SLOT=
V7_MD5=
V7_SHA256=
VERIFY=   (PASS/FAIL + число проверок)
FLASH=    (write ok/readback identical)
ADB_DEVICES=
RO_ADB_SECURE=
ID=
# если неудача:
GETVAR_SECURE=
GETVAR_UNLOCKED=
SECCFG_VALIDATE=   (verdict: orange/green/UNDECIDABLE)
```

Без строки `VERIFY=PASS` и `readback identical=true` образ не считается принятым.
