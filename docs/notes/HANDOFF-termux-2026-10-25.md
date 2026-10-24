# HANDOFF → Termux-агенту: RMX3630 / ADB-авторизация (2026-10-25)

Цель: получить рабочий `adb` (и scrcpy) на realme RMX3630 (MT6789, Android 12,
мёртвый экран). Сейчас **Android загружается, adbd поднят, но `adb devices`
показывает `unauthorized`**. Нужно понять, почему не применяется
`ro.adb.secure=0` из нашего патча boot-рамдиска, и закрыть это.

Всё, что ниже, проверено на устройстве или по извлечённым файлам.
Ничего не удаляй и не «перезалочивай» — см. §7 (безопасность).

---

## 1. Состояние устройства (актуально)

| что | значение |
|---|---|
| разлочка | `seccfg lock_state=3`, RPMB-зеркало `locked=0` (наш блок `11a2d0c1…`) — держится после ребута |
| запись в RPMB | ключ `75a41c1a705af539c502a58758fc61fb0d9f3f290ff9a54b30d8fb48b61e7a97` (SEJ/HACC от MEID) — рабочий |
| `boot_a` | пропатчен (v5): md5 `f0c1674243f465d9bb363a45642d2117`, ramdisk gzip, vbmeta/footer стоковые |
| `metadata`, `userdata` | стёрты (первые 1 МБ / 16 МБ) — после этого Android и загрузился |
| Android | стартует, USB `22d9:2769`, интерфейс ADB (`ff/42/01`), `adb devices → unauthorized` |
| свойства | `ro.adb.secure` остаётся 1 (патч свойств не применился) |

Правильный ритуал включения (иначе preloader ждёт DA и Android не стартует):

```
1) выдернуть кабель
2) Power ~10 с (выключить)
3) Power ~3 с, кабель НЕ вставлять
4) 90 с без кабеля
5) вставить кабель → lsusb / adb devices
```

Для DA (preloader): выключить → **Vol+ & Vol−** + кабель → `22d9:0006`.

---

## 2. Что уже проверено (не повторять)

### 2.1 boot_a и vbmeta (важно!)

`boot_a` — v4-образ с **встроенной vbmeta** `AVB0` на `0x1513000` и `AVBf`-футером
в последних 64 байтах раздела. Если рамдиск пересобрать «как обычно» и он
перерастёт слот `0x194000` (от `0x137f000` до `0x1513000`), vbmeta затирается →
жёсткий сбой загрузки (цикл с вибрацией). Поэтому:

* рамдиск сжат **gzip -9** и укладывается в слот;
* байты `[0x1513000, конец]` копируются **побайтно из стока**;
* LK при `lock=3` вызывает `avb_slot_verify` с `ALLOW_VERIFICATION_ERRORS`
  (потому что `img_auth_required=0`), поэтому hash mismatch **не фатален**;
  проверено: gzip-образ загружается.

### 2.2 Что мы кладём в рамдиск (v5)

```
/force_debuggable        (пустой маркер, корень)
/adb_debug.prop          ro.adb.secure=0, ro.debuggable=1,
                         ro.force.debuggable=1, persist.sys.usb.config=adb
/prop.default            (legacy, бесполезно — читается только в recovery)
/adb_keys                наш pubkey (713 B)
system/etc/ramdisk/build.prop   пропатчен (тоже бесполезно)
```

Плюс **патч самого `init` в рамдиске** (4 байта):

```
VA 0x2F6D14:  93 04 00 36  (tbz w19,#0,0x2F6DA4)  ->  24 00 00 14  (b 0x2F6DA4)
```

Причина: `FirstStageMain` вызывает `setenv("INIT_FORCE_DEBUGGABLE","true")`
только если удались **обе** копии: `/adb_debug.prop` и
`/userdebug_plat_sepolicy.cil`. На user-сборке второго файла нет → env не
выставлялся. Патч делает `setenv` безусловным (файл политики при этом не нужен,
`use_userdebug_policy` остаётся false).

**Результат: всё равно `unauthorized`.**

### 2.3 Что известно про вторую стадию (из извлечённого `/system/bin/init`)

Мы вытащили system (EROFS) и разобрали `init` (3 085 160 B). Ключевые строки:

```
/force_debuggable                      VA 0x17A49, xref 0x124554   (first stage)
/prop.default                          VA 0x2850B, xref 0x156B2C   (только recovery)
/debug_ramdisk/adb_debug.prop          VA 0x337B7 / 0x338EE,
                                       xrefs 0x156FE4, 0x15700C, 0x158CC8
```

Код загрузки adb_debug.prop (вторая стадия):

```
0x156FE4  adrp/add  x0 = "/debug_ramdisk/adb_debug.prop"
0x156FEC  mov w1, #4                    ; R_OK
0x156FF0  bl 0x2D87A0                   ; access()
0x156FF4  cbnz w0, 0x157060             ; нет файла -> пропустить
0x156FF8  mov w0, #2 ; mov x1, xzr
0x157000  bl 0x2D81A0                   ; <-- неопознанный вызов, может отбить
0x157004  tbnz w0, #0, 0x158C80         ; ветка «нет прав»?
0x157028  bl 0x154400                   ; load_properties_from_file()
```

А `/prop.default` читается только после `bl 0xF3170` (похоже на
`IsRecoveryMode()`), т.е. в обычной загрузке пропускается — это подтверждает,
почему v3 не работала.

`ro.adb.secure=1` задаётся в `/system/build.prop` (строки 119–125:
`ro.secure=1`, `ro.adb.secure=1`, `ro.debuggable=0`, `ro.force.debuggable=0`).
`adbd` лежит не в `/system/bin`, а в
`/system/apex/com.google.android.adbd.apex` (8.8 МБ, zip).

---

## 3. Главные открытые вопросы (по приоритету)

**Q1. Тот ли `init` исполняется как first stage?**
Мы патчили `init` из **boot-рамдиска**. Но на GKI-устройствах с `vendor_boot`
ядро получает initramfs как объединение boot-рамдиска и vendor-рамдиска; если в
`vendor_boot_a` тоже есть `init`, он может перекрыть наш. Тогда наш патч
`0x2F6D14` и файлы не работают — что и наблюдаем.

Шаги:
1. Дампнуть `vendor_boot_a` (64 МБ) через DA и посмотреть, есть ли внутри
   ramdisk (`init`, `force_debuggable`, `adb_debug.prop`), каким кодеком сжат.
2. Сравнить размер/хэш `init` из boot-рамдиска (3 143 536 B) и из
   `/system/bin/init` (3 085 160 B) — разные сборки.
3. Если `init` есть в vendor_boot — перенести туда маркер+adb_debug.prop
   (и, при необходимости, тот же патч 0x2F6D14).

**Q2. Не отбивает ли `0x2D81A0` загрузку свойств?**
Идентифицировать функцию (рядом строки «Do not have permissions to set … in
property file» / `property_set_fd`), проверить, при каких условиях она
возвращает 1. Если это SELinux-проверка типа `build_prop`, то `ro.adb.secure`
из adb_debug.prop может отбрасываться — тогда нужен другой ключ (например,
`ro.debuggable`, который имеет другой контекст) или патч init.

**Q3. Срабатывает ли вообще first stage?**
Проверить косвенно: если в рамдиске **убрать** `/force_debuggable` и заменить
`/debug_ramdisk`-tmpfs чем-то наблюдаемым — нельзя. Альтернатива: посмотреть,
меняется ли лог загрузки (expdb пуст, UART нет). Остаётся статический анализ +
сравнение ramdisk'ов из boot/vendor_boot.

---

## 4. Артефакты (пути и контрольные суммы)

| файл | что | md5 / размер |
|---|---|---|
| `/home/musin/system_a.erofs` | дамп `system_a` (EROFS) | `f66645e40702d60067b25dfba4e6b4e7`, 888 131 584 B |
| `/tmp/sysroot/` | распакованный system (fsck.erofs) | 1.4 ГБ |
| `/tmp/sysroot/system/bin/init` | вторая стадия init | 3 085 160 B |
| `/tmp/sysroot/system/build.prop` | свойства system | 8 168 B |
| `/tmp/sysroot/system/apex/com.google.android.adbd.apex` | adbd | 8 822 784 B |
| `/home/musin/boot_patched.img` | текущий boot (v5) | `f0c1674243f465d9bb363a45642d2117`, 0x4000000 B |
| `/home/musin/boot_a_backup_20261024_233245.img` | сток boot_a (до v5) | (в логе: md5 `76e089fa…`, это был уже v4) |
| `/home/musin/boot_a_backup_20261024_225408.img` | сток boot_a до v4 | `356320597c88669f032e9736e5f906ce` |
| `/home/musin/seccfg_backup.bin`, `…214627.bin` | сток seccfg | `12a94a3ffbfc1a7f344e1dd6837b359a` |
| `/home/musin/rpmb_mirror_locked.bin` | зеркало locked=1 | `2374972dbf75743b4502861d22d84875` |
| `/home/musin/rpmb_mirror_new.bin` | зеркало locked=0 | `11a2d0c1cb998bae544ea78ae05c0d42` |

Скрипты (в `/home/musin/`): `run_flash_boot_patched.sh`,
`run_rpmb_unlock_mirror.sh`, `run_unlock_state_check.sh`,
`run_super_extract.sh`, `run_write_reach.sh`, `run_rpmb_probe.sh`,
`run_rollback_stock.sh`, `run_seccfg_snapshot.sh`, `watch_usb.sh`.
Обёртки предполагают preloader (`22d9:0006`) и свежий CWD
(`OPLUS_PATCH_F804_STUB` НЕ включать).

---

## 5. Как воспроизвести ключевые вещи

### 5.1 Дамп system / чтение файлов
```bash
cd /home/musin/mtkclient
./run_super_extract.sh --dump /home/musin/system_a.erofs      # ~30-60 c
sudo apt install -y erofs-utils
mkdir -p /tmp/sysroot && fsck.erofs --extract=/tmp/sysroot /home/musin/system_a.erofs
```
Разбор LP (уже реализован в `docs/notes/super_extract.py`): контейнер в `super`
начинается с `0x1000` (geometry), заголовок — `0x3000`; дескрипторы таблиц
лежат на `0x50` (лишний 56-байтный блок), смещения таблиц — от `header_size`;
разделы называются `system_a`, `vendor_a`, … (`super_extract.py` уже это умеет).

### 5.2 Пересборка boot с нужным рамдиском
```bash
python docs/notes/build_boot_gzip.py            # берёт сток 225408, кладёт патч
python docs/notes/boot_ramdisk_patch.py --list --in /home/musin/boot_a_backup_20261024_225408.img
```
Требования: gzip ≤ 0x194000, vbmeta/footer из стока не двигать, иначе цикл.

### 5.3 Проверка результата
```bash
adb devices
adb shell getprop ro.adb.secure   # цель: 0
adb shell id                      # цель: uid=0
```

---

## 6. Что сделать дальше (порядок)

1. **Q1**: дампнуть `vendor_boot_a`, вытащить рамдиск, проверить наличие `init`
   и формат. Если `init` там — патчить его/добавить файлы туда.
2. Если `init` только в boot — **Q2**: идентифицировать `0x2D81A0` и ветку
   `0x158C80` в `/system/bin/init`; понять, что мешает загрузке свойств.
   Полезно: `strings` вокруг, xrefs на «Do not have permissions»,
   `plat_property_contexts` (`ro.adb.secure u:object_r:build_prop:s0 exact bool`).
3. Если оба пути глухие — альтернатива: патч `adbd` внутри APEX
   (`com.google.android.adbd.apex` — zip; внутри `lib64/adbd` или `bin/adbd`),
   но APEX подписан; проще подменить APEX нельзя, потребуется обход.
4. Ещё вариант: `ro.debuggable=1` вместо `ro.adb.secure=0` (у `ro.debuggable`
   другой property-context, может пройти там, где `build_prop` отбивается).

---

## 7. Безопасность / откат

* **Никогда** не менять `seccfg`/RPMB без бэкапа: сток seccfg —
  `/home/musin/seccfg_backup.bin` (`12a94a3f…`), зеркало locked=1 —
  `/home/musin/rpmb_mirror_locked.bin` (`2374972d…`).
* Откат boot: `BOOT_RESTORE=/home/musin/boot_a_backup_20261024_225408.img FLASH_GO=1 ./run_flash_boot_patched.sh`.
* Откат unlock: `MIRROR_RESTORE=1 ./run_rpmb_unlock_mirror.sh` (зеркало),
  затем сток seccfg из бэкапа.
* **Не** стирать `metadata`/`userdata` без нужды — данные уже стёрты, но
  повторный вайп ничего не даст.
* Не включать `OPLUS_PATCH_F804_STUB` (это глушит запись целиком).
* Все записи — только с `*_GO=1` и после readback.

---

## 8. Документы

* `docs/notes/STATUS-rmx3630-2026-10-24.md` — сводка кампании;
* `docs/notes/reverse/re-unlock-campaign-2026-10-24.md` — хронология и доказательства;
* `docs/notes/reverse/re-consistency-audit-2.md` — аудит противоречий в доках;
* `docs/notes/campaign-status-rmx3630.md` — полный журнал (§1–§31);
* `docs/notes/reverse/re-lk-rpmb-lock.md`, `re-lk-seccfg.md` — LK/RPMB/seccfg.

Удачи. Главное сейчас — ответить на Q1 (чей `init` реально исполняется).
