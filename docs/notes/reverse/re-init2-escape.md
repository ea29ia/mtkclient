# Task H: можно ли включить `load_debug_prop` без LK/seccfg

Дата: 2026-10-25. Ветка `oplus-mt6789-unlock`. **Офлайн: устройство не трогали,
DA не запускали, ничего не флешили.** Все выводы — из стоковых образов и из
байтов, сгенерированных на копиях в `/tmp/re_init2_spec/`.

Вход: `docs/notes/PLAN-q1-q2-2026-10-25.md`, `re-lk-initrd-and-vbst.md`,
`re-init-prop-gate.md`, `re-adbd-apex-route.md`, `re-v6-build.md`,
`re-vendor-boot-q1.md`.

Артефакты (не менялись): `docs/notes/rmx3630-lk/boot.img` (sha256 `8c9ef539…`),
`/tmp/fw/system_init` (3 085 160 B, `a458669b…`), `/tmp/initwork/ramdisk/init`
(3 143 536 B, `b8088eb2…`), `/tmp/fw/sysroot/**` (system.img через `fsck.erofs`),
`/tmp/fw/frag0_via_lz4.bin` (vendor-рамдиск, 916 записей).
Новое: `docs/notes/re_init2_spec_test.py` (self-test, exit 0).

---

## 0. Вердикт (кратко)

| # | маршрут | статус | что решает |
|---|---|---|---|
| **R4c** | **`adb_debug.prop` внутрь rootfs-каталога `/debug_ramdisk/`** | **РАБОТАЕТ, риск низкий** | гейт вообще не нужен: после `umount()` нижний слой rootfs снова виден, и `PropertyInit()` читает prop-файл |
| R1 | redirect exec на `/init2` из рамдиска | **НЕВОЗМОЖНО (SELinux)** | `entrypoint` для `rootfs` у `init` нет; перемаркировать нельзя (`init_exec ∈ exec_type`, `init` не имеет `relabelto`) |
| R2 | bind-mount поверх `/system/bin/init` | **НЕВОЗМОЖНО** | тот же `entrypoint`-барьер + нужен инжект кода после `DoFirstStageMount`, до `execv` — места нет |
| R3 | перепаковка `system_a` + пересборка `vbmeta_system` | **ЗАБЛОКИРОВАН, дорого** | ключ OPLUS (sha1 `3c5f7b18…`) невоспроизводим; толерантность userspace = тот же `IsDeviceUnlocked()` |
| R4a | другой property-файл без гейта | **НЕТ** | все 12 файлов после `/system/build.prop` живут на разделах, смонтированных в first stage |
| R4b | `/adb_keys` в рамдиске | **НЕТ (на user-сборке)** | rootfs = genfs (`rootfs:s0`), `restorecon` не может перемаркировать; у `adbd` нет `read` на `rootfs` |

Одной строкой: **`/init2` не спасает, потому что политика не даёт `init`
исполнять что-либо, кроме `init_exec`, а `init_exec` есть только у
`/init` (занят PID1) и `/system/bin/init` (EROFS). Зато гейт можно обойти
данными: положить prop-файл в нижний слой `/debug_ramdisk`, который
открывается после `umount()`.**

---

## 1. Ground truth: гейт, цепочка exec, порядок монтирования

### 1.1 Гейт в `/system/bin/init` (`SecondStageMain`)

```
$ r2 -q -c 's 0x1344a0; pd 30' /tmp/fw/system_init
0x001344a4  adrp x0, 0x1c000 ; add x0,x0,#0xf41   ; "INIT_FORCE_DEBUGGABLE"
0x001344ac  bl   getenv
0x001344b0  60 04 00 b4   cbz x0, 0x13453c
0x001344b4  mov x20, x0
0x001344b8  bl   android::fs_mgr::AvbHandle::IsDeviceUnlocked()
0x001344bc  00 04 00 36   tbz w0, 0, 0x13453c        <-- ГЕЙТ (4 байта)
...
0x0013452c  bl   android::init::PropertyInit()       ; /debug_ramdisk ещё смонтирован
0x00134530  bl   android::init::UmountSecondStageRes()
0x00134534  bl   android::init::UmountDebugRamdisk()
0x0013453c  (else) unsetenv
0x00134548  bl   android::init::UmountDebugRamdisk() ; снимает ДО PropertyInit
0x0013454c  bl   android::init::PropertyInit()
```

Байты сайта: `00 04 00 36` (VA 0x1344BC == файловый offset, ET_DYN).

### 1.2 Цепочка exec

* PID1 = `/init` **из boot-рамдиска** (`b8088eb2…`) — boot cpio накладывается
  поверх vendor cpio (`re-lk-initrd-and-vbst.md` §2.6).
* `FirstStageMain`: `DoFirstStageMount()` вызывается по `0x2F6FBC`, а
  `execv("/system/bin/init", {"/system/bin/init","selinux_setup"})` — по
  `0x2F70D8`, т.е. **/system уже смонтирован**:
  ```
  2f6fb8: eor  w0, w24, #1
  2f6fbc: bl   0x2fd7e4          ; DoFirstStageMount
  2f70d8: bl   0x48f284          ; execv
  ```
  Подтверждение из fstab (`first_stage_ramdisk/fstab.mt6789`, vendor-рамдиск):
  `system /system erofs ro … first_stage_mount` (то же для vendor/product/
  system_ext/vendor_dlkm/odm_dlkm). Значит по пути `/system/bin/init` в момент
  exec лежит **EROFS-файл**, а не ramfs-копия из vendor-рамдиска.
* Второй exec (re-exec) делает уже system-init:
  ```
  174e2c  adrp x21, 0x23000 ; add x21,x21,#0x8d8   ; ОДИН литерал "/system/bin/init"
  174e34  mov  x0, x21
  174e3c  bl   selinux_android_restorecon           ; (a) restorecon того же литерала
  ...
  174ea8  mov  x0, x21                              ; (b) execv того же литерала
  174eac  str  x21, [sp, #512]                      ;     argv[0] = тот же литерал
  174eb8  bl   execv
  ```
  `argv[1]` для re-exec — отдельная строка `"second_stage"` (`VA 0x1A3C9`),
  а не `selinux_setup`.

### 1.3 `/debug_ramdisk` — это tmpfs, создаваемый first stage

```
2f6298  adrp x1,0x206000 ; add x1,x1,#0xac7   ; "/debug_ramdisk"  (target)
2f62a0  adrp x0,0x20d000 ; add x0,x0,#0x9a2   ; "tmpfs"           (source)
2f62a8  adrp x4,0x200000 ; add x4,x4,#0x37a   ; "mode=0755"
2f62b4  mov  w3, #0xe                         ; MS_NOSUID|MS_NODEV|MS_NOEXEC
2f62b8  bl   0x4a8960                         ; mount("tmpfs","/debug_ramdisk","tmpfs",0xE,"mode=0755")
```

`UmountDebugRamdisk` = ровно `umount("/debug_ramdisk")`, без `rmdir` и без
`MNT_DETACH` (`0x139A28 bl umount`); ошибка только логируется.
**Следствие: под точкой монтирования остаётся обычный каталог rootfs из cpio
(`debug_ramdisk`, mode 040755, ino 300000). Всё, что в нём лежит, снова видно
после `umount()`.**

---

## 2. R1 — redirect exec на `/init2` (разобран и отклонён)

### 2.1 Полная спека байтов (валидирована, но сама по себе бесполезна)

| # | бинарь | offset | было | стало | смысл |
|---|---|---|---|---|---|
| A1 | `/system/bin/init` (копия) | `0x1344BC` | `00 04 00 36` | `1f 20 03 d5` | `tbz w0,#0,0x13453C` → `nop`; гейт = только env |
| A2 | `/system/bin/init` (копия) | `0x1344B0` | `60 04 00 B4` | `1f 20 03 d5` | `cbz x0,…` (getenv==NULL) → `nop` |
| A2 | `/system/bin/init` (копия) | `0x1344BC` | `00 04 00 36` | `1C 00 00 14` | `tbz` → `b 0x13452C` (PropertyInit) — env больше не нужен |
| A3 | `/system/bin/init` (копия) | `0x238D8` | `2F 73 79 73 74 65 6D 2F 62 69 6E 2F 69 6E 69 74 00` (`/system/bin/init`) | `2F 69 6E 69 74 32 00` + 10×`00` (`/init2`) | путь exec **и** restorecon (один литерал!) |
| A4 | boot-`/init` (копия) | `0x13BDB` (VA 0x213BDB) | то же | то же | первый exec (`selinux_setup`) |
| P1 | boot-`/init` (копия) | `0xF6D14` (VA 0x2F6D14) | `93 04 00 36` | `24 00 00 14` | уже прошит в v5 |

`A1`/`A2`: расходится 4 / 7 байт (проверено `cmp -l`, см. §6). `A3`/`A4`:
14 байт на литерал.

### 2.2 (a) какой путь использует re-exec и надо ли править оба

Да, оба. Первый `execv` (first stage) идёт по литералу boot-`/init`
(`VA 0x213BDB`, **единственная** копия строки в этом бинаре; xref —
`0x2F7088`, второй xref `0x2F720C` — текст ошибки). Второй exec делает
system-init по литералу `0x238D8`; **в system-init это один и тот же литерал
для `restorecon`, `argv[0]` и `execv`** (см. §1.2). Поэтому «перенацелить
только exec» нельзя, не затронув `restorecon`.

### 2.3 (b) SELinux: файл `/init2` исполнить как `init` нельзя

Факты (номера строк — в извлечённых файлах `/tmp/fw/sysroot/system/etc/selinux/`):

| факт | где |
|---|---|
| `/init u:object_r:init_exec:s0` | `plat_file_contexts:376` |
| `/system/bin/init u:object_r:init_exec:s0` | `plat_file_contexts:451` |
| `/debug_ramdisk u:object_r:tmpfs:s0` | `plat_file_contexts:427` |
| `(genfscon rootfs "/" (u object_r rootfs …))` | `plat_sepolicy.cil:320` |
| `(fsuse xattr erofs …)` — EROFS метится xattr'ами, rootfs — нет | `plat_sepolicy.cil:76` |
| `(allow init init_exec (file (read getattr map execute open entrypoint)))` | `plat_sepolicy.cil:23414` |
| `(allow init rootfs (file (read getattr map execute open)))` — **без** `entrypoint` | `plat_sepolicy.cil:22731, 22769` |
| `(allow init rootfs (file (relabelfrom)))` | `plat_sepolicy.cil:12644` |
| `(allow init base_typeattr_521 (file (relabelto)))`, где `base_typeattr_521 = file_type ∧ ¬(… exec_type …)` | `plat_sepolicy.cil:12657`, `31195` |
| `allow init rootfs (file (… entrypoint …))` — **отсутствует** (grep пуст) | — |

Разбор:

1. Файл в корне rootfs (`/init2`) получает `rootfs:s0` по `genfscon rootfs "/"`.
   Для `exec` ядро всегда проверяет `FILE__ENTRYPOINT`; правило есть только на
   `init_exec`. `execute` без `entrypoint` не помогает → `execv` вернёт `EACCES`
   → `PLOG(FATAL) "execv(...) failed"` → bootloop.
2. Перемаркировать нельзя: `restorecon("/init2")` шёл бы `relabelfrom rootfs`
   (разрешено) + `relabelto init_exec`, но `init_exec ∈ exec_type`, а
   `exec_type` исключён из `base_typeattr_521`. `relabelto init_exec` есть
   только у `kernel` (`cil:13114`).
3. Если оставить `restorecon("/system/bin/init")` (т.е. патчить не литерал, а
   одну инструкцию загрузки пути), то `restorecon` отработает по EROFS-файлу,
   а `/init2` останется `rootfs:s0` → всё равно `EACCES`.
4. Других «готовых» контекстов нет:
   * `/system/bin/init` в **ramfs** (vendor-рамдиск) — путь перекрыт монтированием
     `/system` (§1.2), а сам inode тоже `rootfs:s0`;
   * `/debug_ramdisk/*` — tmpfs; файлы, созданные `init` на tmpfs, получают
     `init_tmpfs` (`typetransition init tmpfs file init_tmpfs`, `cil:22729`), а
     `allow init init_tmpfs` — только `read write getattr map` (`cil:22730`),
     без `execute`/`entrypoint`;
   * `/second_stage_resources` — тот же tmpfs-механизм.
   Итог: **пути с пригодным контекстом, достижимого в момент exec, не
   существует.**

### 2.4 (c) нужен ли `/system/bin/init` как argv[0] / subcontext / self-exe

Нет. `main()` в system-init диспетчеризует по `argv[1]`
(`"selinux_setup"`/`"second_stage"`/`"subcontext"`), а basename `argv[0]`
проверяется только для `ueventd`/`watchdogd`; `/init2` в эти ветки не попадает.
`/proc/self/exe` в re-exec не используется — путь берётся из литерала
(`0x238D8`), а `setenv("SELINUX_STARTED_AT", getpid())` к пути отношения не
имеет. Subcontext-forking включается только при `argv[1]=="subcontext"`.

### 2.5 Вердикт R1

Механически патчи валидны (см. self-test §6), но маршрут **невозможен**:
единственный барьер — `entrypoint`/`init_exec`, и он не обходится патчем
инита. Пункт (b) убивает и R1, и R2.

---

## 3. R2 — bind-mount поверх `/system/bin/init`

Не только «нужен код»: **это тот же SELinux-тупик**. Bind-mount подставляет
*inode* из rootfs (`rootfs:s0`), а `restorecon("/system/bin/init")` в
`SetupSelinux` попытается сделать `relabelto init_exec` — `init` этого не может
(`cil:12657/31195`) → `PLOG(FATAL) "restorecon failed of /system/bin/init
failed"`.

Плюс механически: единственный существующий bind-mount (`0x2F6F60`,
`mount("/first_stage_ramdisk","/first_stage_ramdisk",NULL,MS_BIND,NULL)`)
выполняется **до** `DoFirstStageMount` (`0x2F6FBC`), поэтому монтирование
`/system` его перекроет; новый вызов надо ставить в окно
`0x2F6FC0…0x2F70D4` (перед `execv`), т.е. ~6 новых инструкций в ET_EXEC с
фиксированными vaddr; code cave не найден, а расширение `.text` сдвигает все
последующие оффсеты. **Нецелесообразно.**

---

## 4. R3 — перепаковка `system_a` (EROFS) + `vbmeta_system`

Стоимость и блокеры:

| параметр | значение |
|---|---|
| raw system | 877 805 568 B (837 MiB), sparse-образ 884 732 164 B |
| dm-verity hashtree | 6 922 240 B, root digest `fa1a75fd…` в `vbmeta_system` |
| запись | ~885 MB по DA/UFS: грубо 15–30 s запись + 10–20 s verify (плюс риск сбоя питания) |
| инструменты | нужен `mkfs.erofs` (офлайн есть только `fsck.erofs`), затем `avbtool add_hashtree_footer`, затем подпись `vbmeta_system` |
| ключ | `vbmeta_system` подписан `SHA256_RSA2048`, ключ OPLUS sha1 `3c5f7b18…`; **закрытого ключа нет** |

Ключевой блокер не в размере: после правки `/system/bin/init` меняется
hashtree, значит нужен новый `vbmeta_system`. Подписать своим ключом можно, но
тогда рушится цепочка `vbmeta.img → vbmeta_system` (там зашит публичный ключ
OPLUS). Толерантность к этому в userspace определяется **тем же**
`fs_mgr::IsAvbPermissive()` ⇔ `IsDeviceUnlocked()` ⇔ `verifiedbootstate=="orange"`.
То есть R3 работает только в том мире, где гейт уже пройден — а там он не нужен.
`vendor_boot`-прецедент («vbmeta unsigned → пересчитываем hash») на `system`
**не переносится**: у `vbmeta_system` есть подпись и chain.

**Вердикт: заблокирован; как «страховка» не годится.**

---

## 5. R4 — что ещё можно, не трогая LK/seccfg

### 5.1 R4a: другой property-файл, который грузится без гейта

`PropertyLoadBootDefaults` (VA `0x156640`) грузит 13 источников; позже
`/system/build.prop` (№5, там `ro.adb.secure=1`, строка 121) идут только
разделы:

| № | файл | можно ли подсунуть из рамдиска |
|---|---|---|
| 4 | `/second_stage_resources/system/etc/ramdisk/build.prop` | да, но **раньше** №5 → перекрывается |
| 5 | `/system/build.prop` | EROFS |
| 7,8,10 | `/vendor/{default,build,euclid_build}.prop` | `/vendor` = `first_stage_mount` |
| 9 | `/vendor_dlkm/etc/build.prop` | `first_stage_mount` |
| 11 | `/odm_dlkm/etc/build.prop` | `first_stage_mount` |
| 12 | product / system_ext / odm | `first_stage_mount` (fstab.mt6789) |
| 13 | `/debug_ramdisk/adb_debug.prop` | **гейт** |

Все `first_stage_mount`-разделы смонтированы до `execv` (§1.2), т.е. до
`PropertyInit` —ramfs-файлы под ними не видны. `access()` в №13 смотрит
`/debug_ramdisk/adb_debug.prop` (VA `0x156FE4`, `0x157028`). **Свободного
незащищённого файла нет.**

### 5.2 R4b: `/adb_keys` (выглядит соблазнительно, но на user-сборке мертво)

`adbd` действительно читает `/adb_keys` **первым**:
`libadbd_auth.so`, `adbd_auth_get_public_keys` (`0x100E0`) перебирает массив
`{"/adb_keys" (0x3349), "/data/misc/adb/adb_keys" (0x3603)}` с `access(path,
R_OK)`, и `adbd_auth_verify` (`0xBBE8C`) вызывает его при `AUTH_SIGNATURE`
(`handle_packet+0x…`, `0xA502C`). `auth_required` в adbd — статическая `1`
(файл-offset `0x1E4404`).

Но файл должен быть **прочитан** `adbd` (домен `adbd`), а:

* `rootfs` метится genfs (`cil:320`), перемаркировка `restorecon /adb_keys`
  (init.rc:48-49) на genfs невозможна (нет `fsuse` для rootfs);
* у `adbd` есть `read` только на `adb_keys_file` (`cil:17074`), а
  `allow adbd rootfs (file …)` **отсутствует** (есть только `dir`/`lnk_file`).

Значит `/adb_keys` в рамдиске останется `rootfs:s0` → `EACCES` → fallback на
`/data/misc/adb/adb_keys` (пусто). На permissive/userdebug это бы сработало, на
`ro.build.type=user` — нет.

### 5.3 R4c — **рекомендуемый**: prop-файл в нижнем слое `/debug_ramdisk`

Идея: гейт управляет только тем, **снят ли tmpfs** над `/debug_ramdisk`.
`PropertyInit()` читает `/debug_ramdisk/adb_debug.prop` в обоих случаях, если
файл есть **и на tmpfs, и в rootfs-каталоге под ним**:

| ветка | что видит `PropertyInit` | чем закрывается |
|---|---|---|
| гейт пройден (`orange && env=="true"`) | `PropertyInit` **до** `umount` → tmpfs, куда first stage скопировал `/adb_debug.prop` | маркер `/force_debuggable` + `/adb_debug.prop` в корне cpio (как в v5) |
| гейт не пройден (наш случай) | `umount` **до** `PropertyInit` → нижний слой rootfs | **новый файл `debug_ramdisk/adb_debug.prop` в cpio** |
| `umount` вернул `EBUSY` | tmpfs остаётся | снова tmpfs-копия |

Почему это законно по SELinux: файл читает `init`, а
`(allow init rootfs (file (read getattr map execute open)))` (`cil:22731`)
покрывает `rootfs:s0`; контекст для property-check берётся из **пути**
(`/debug_ramdisk/...` → `scon = u:r:init:s0`), а `ro.adb.secure` =
`u:object_r:build_prop:s0 exact bool` (`plat_property_contexts:976`) и
`(allow init property_type (property_service (set)))` (`cil:12810`) → значение
принимается. `adb_debug.prop` — последний файл в map и перекрывает
`/system/build.prop` (см. `re-init-prop-gate.md` §4.2).

**Это не требует ни одного патча ELF, ни `vendor_boot`, ни EROFS, ни LK, и не
зависит от `verifiedbootstate`.**

---

## 6. Байтовая спека рекомендуемого маршрута (R4c)

Меняется **только boot-рамдиск**. `/init` остаётся стоковым (sha256
`b8088eb2…`), P1 не нужен (но и не мешает).

### 6.1 Три новые записи cpio (newc, добавляются перед `TRAILER!!!`)

Точка вставки в стоковом cpio: `0x300194` (3 146 132). Блок вставки — 564 B,
sha256 `e168b2aeed12ae3ad66724aecd84247b7eed6fcc8c637a330d18e6e5e5a8c307`.

| имя | cpio-offset | размер | mode | ino | данные |
|---|---|---|---|---|---|
| `force_debuggable` | `0x300194` | 0 | `0100644` | 300015 | — |
| `adb_debug.prop` | `0x300214` | 81 | `0100644` | 300016 | см. §6.2 |
| `debug_ramdisk/adb_debug.prop` | `0x3002E8` | 81 | `0100644` | 300017 | то же |

Заголовки (110 B + имя + pad) — ровно то, что печатает `cpio_entry()`:

```
force_debuggable             : 070701 000493EF 000081A4 00000000 00000000
                               00000001 00000000 00000000 00000000 00000000
                               00000000 00000011 00000000  "force_debuggable\0"
adb_debug.prop               : 070701 000493F0 000081A4 … 00000051 …
                               0000000F 00000000  "adb_debug.prop\0\0\0\0"
debug_ramdisk/adb_debug.prop : 070701 000493F1 000081A4 … 00000051 …
                               0000001D 00000000  "debug_ramdisk/adb_debug.prop\0…"
```

(порядок полей newc: ino, mode, uid, gid, nlink, mtime, filesize, devmajor,
devminor, rdevmajor, rdevminor, namesize, check).

### 6.2 Полезная нагрузка (81 B, sha256 `84bc904d…`)

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

Это тот же payload, что уже прошит в v5 (`build_v6_dual.ADB_PROPS`).

### 6.3 Размеры

| | было (сток) | стало |
|---|---|---|
| cpio | 3 146 496 | 3 147 060 (+564) |
| рамдиск | lz4 1 649 781 | **gzip -9 1 419 826** |
| слот до vbmeta | 1 654 784 | запас **234 958 B** |
| header `.ramdisk_size` @0x0C | 0x192C75 | 0x15AA32 (1 419 826) |

### 6.4 Точные шаги пересборки (переиспользование примитивов)

```python
import gzip, os, struct, sys
sys.path.insert(0, "docs/notes")
import build_v6_dual as B          # импорт, файл не меняется
os.makedirs("/tmp/v7", exist_ok=True)

img = open("docs/notes/rmx3630-lk/boot.img", "rb").read()
assert B.sha(img) == "8c9ef5391a6f90fa43bcf46cdd4eeb4bdbae9b55595b9bdb2e4d84c20d45a8c9"
p    = B.boot_parse(img)                       # v4, hdr 0x630, rd @0x1378000
foot = B.avb_footer(img); vb_off = foot["vbmeta_offset"]   # 0x150C000
raw, _ = B.lz4_legacy_blocks(img[p["rd_off"]:p["rd_off"] + p["ramdisk_size"]])

ino  = max(e["ino"] for e in B.cpio_walk(raw))
adds = [B.cpio_entry("force_debuggable",            b"",        0o100644, ino + 1),
        B.cpio_entry("adb_debug.prop",              B.ADB_PROPS, 0o100644, ino + 2),
        B.cpio_entry("debug_ramdisk/adb_debug.prop", B.ADB_PROPS, 0o100644, ino + 3)]
new  = B.cpio_insert(raw, adds)                # вставка перед TRAILER!!!
comp = gzip.compress(new, 9, mtime=0)
assert len(comp) <= vb_off - p["rd_off"]

out = bytearray(img)                           # хвост [vbmeta..EOF) — сток
struct.pack_into("<I", out, 0x0C, len(comp))
out[p["rd_off"]:vb_off] = comp + bytes(vb_off - p["rd_off"] - len(comp))
open("/tmp/v7/boot_v7.img", "wb").write(out)   # НЕ флешить в этой задаче
```

Проверка (не `build_v6_dual.py verify` — его 43 инварианта привязаны к v6/P1):

```bash
python3 docs/notes/re_init2_spec_test.py            # exit 0 (см. §7)
# независимо: /init не изменился, записи на месте, рамдиск влезает
python3 - <<'EOF'
import gzip,sys; sys.path.insert(0,'docs/notes'); import build_v6_dual as B
d=open('/tmp/v7/boot_v7.img','rb').read(); p=B.boot_parse(d)
cp=gzip.decompress(d[p['rd_off']:p['rd_off']+p['ramdisk_size']])
e={x['name']:x for x in B.cpio_walk(cp)}
print(len(cp), B.sha(e['init']['data'])[:16], sorted(k for k in e if 'adb' in k or 'force' in k))
EOF
```

`vendor_boot` **не трогаем** — этим снимается риск из `re-v6-build.md` §3.3.

### 6.5 Что докажет успех на устройстве

```
adb devices -l                 # ожидается "device" (не unauthorized), без диалога
adb shell getprop ro.adb.secure      # "0"
adb shell getprop ro.debuggable      # "1"
adb shell getprop ro.boot.verifiedbootstate   # диагностика: green/yellow/orange
```
Последняя команда — фальсификатор: если `orange`, маршрут R4c всё равно
работает (через tmpfs-копию), но тогда был бы достаточен и v5.

Откат: единственная изменяемая партиция — `boot_a`; сток `boot.img`
(`8c9ef539…`) прошивается обратно штатным `writePartition`.

---

## 7. Валидация спеки (self-test, exit 0)

```
$ python3 docs/notes/re_init2_spec_test.py
==============================================================================
A. R1 candidate spec (documented, REJECTED on SELinux grounds)
==============================================================================
PASS  stock boot.img sha256 8c9ef5391a6f90fa...
PASS  /system/bin/init sha256 a458669ba60984ce...
PASS  boot ramdisk /init sha256 b8088eb2b895da03...
      site 0x1344BC: 00 04 00 36 -> 1f 20 03 d5  (tbz w0,#0,0x13453C -> nop)
PASS  A1 system-init gate nop: cmp -l shows exactly 4 changed byte(s) at 0x1344BC, 0x1344BD, 0x1344BE, 0x1344BF
PASS  A1 patched ELF still parses [DYN (Position-Independent Executable file) / AArch64]
      site 0x1344B0: 60 04 00 b4 -> 1f 20 03 d5  (cbz x0 -> nop)
      site 0x1344BC: 00 04 00 36 -> 1c 00 00 14  (tbz -> b 0x13452C)
PASS  A2 branch decodes to PropertyInit @0x13452C
PASS  A2 system-init gate bypass: cmp -l shows exactly 7 changed byte(s) at 0x1344B0, 0x1344B1, 0x1344B2, 0x1344B3, 0x1344BC, 0x1344BD, 0x1344BF
PASS  A2 patched ELF still parses [DYN (Position-Independent Executable file) / AArch64]
PASS  A3 system-init literal @0x238D8: stock bytes are b'/system/bin/init\x00'
PASS  A3 system-init literal @0x238D8: cmp -l shows exactly 14 changed byte(s) at 0x238D9, 0x238DA, 0x238DB, 0x238DD, 0x238DE, 0x238DF, 0x238E0, 0x238E1, 0x238E2, 0x238E3, 0x238E4, 0x238E5, 0x238E6, 0x238E7
PASS  A3 system-init literal @0x238D8: patched ELF still parses [DYN (Position-Independent Executable file) / AArch64]
PASS  A4 boot-init literal @0x13BDB: stock bytes are b'/system/bin/init\x00'
PASS  A4 boot-init literal @0x13BDB: cmp -l shows exactly 14 changed byte(s) at 0x13BDC, 0x13BDD, 0x13BDE, 0x13BE0, 0x13BE1, 0x13BE2, 0x13BE3, 0x13BE4, 0x13BE5, 0x13BE6, 0x13BE7, 0x13BE8, 0x13BE9, 0x13BEA
PASS  A4 boot-init literal @0x13BDB: patched ELF still parses [EXEC (Executable file) / AArch64]

==============================================================================
B. Recommended route R4c: cpio only, zero ELF bytes changed
==============================================================================
      stock ramdisk: lz4-legacy 1649781 B @0x1378000, slot budget 1654784 B, cpio 3146496 B
PASS  stock cpio has directory /debug_ramdisk (mode 040755)
PASS  stock cpio /init is the first-stage binary (sha256 b8088eb2...)
PASS  stock cpio has no /debug_ramdisk/adb_debug.prop
PASS  /adb_debug.prop payload 81 B, sha256 84bc904deff1cc6c
PASS  cpio entry count 15 -> 18 (only additions)
PASS  new entry force_debuggable                   size 0 mode 0100644
PASS  new entry adb_debug.prop                     size 81 mode 0100644
PASS  new entry debug_ramdisk/adb_debug.prop       size 81 mode 0100644
PASS  rootfs-layer prop content is byte-exact
PASS  cpio insert is a pure insertion before TRAILER (stock bytes intact)
PASS  recommended route leaves /init byte-identical (no ELF patch)
PASS  first-stage /init extracted from v7 still parses [EXEC (Executable file) / AArch64]
PASS  gzip -9 ramdisk 1419826 B fits slot (1654784 B), slack 234958 B

==============================================================================
C. Policy assertions the verdict rests on
==============================================================================
PASS  plat_file_contexts: /init -> u:object_r:init_exec:s0
PASS  plat_file_contexts: /system/bin/init -> u:object_r:init_exec:s0
PASS  plat_file_contexts: /debug_ramdisk -> u:object_r:tmpfs:s0
PASS  plat_sepolicy.cil: genfscon rootfs "/" -> rootfs (no per-file xattr)
PASS  plat_sepolicy.cil: no (fsuse ...) for rootfs -> labels are genfs, not xattr
PASS  plat_sepolicy.cil: allow init init_exec (file (entrypoint)) exists
PASS  plat_sepolicy.cil: NO allow init rootfs (file (entrypoint)) -> /init2 exec denied
PASS  plat_sepolicy.cil: allow init rootfs (file (read ... open)) -> prop file readable
PASS  plat_sepolicy.cil: allow init property_type (property_service (set))
PASS  plat_property_contexts: ro.adb.secure -> build_prop (init may set it)
PASS  plat_sepolicy.cil: allow init rootfs (file (relabelfrom)) [why /adb_keys was considered]
PASS  plat_sepolicy.cil: adbd may read adb_keys_file, but has no read on rootfs
PASS  plat_sepolicy.cil: NO allow adbd rootfs (file ...) -> /adb_keys on rootfs unreadable
PASS  init.rc:31-49 restores /adb_keys (needs relabel, which genfs rootfs cannot do)

Artifacts (copies only, not flashable images):
  boot_v7.cpio                  3147060 B  37c91078139851d3
  boot_v7.ramdisk.gz            1419826 B  eeae256123544d57
  init.A4                       3143536 B  f65438568bae2e9b
  init.from_v7                  3143536 B  b8088eb2b895da03
  sys_init.A1                   3085160 B  f48fed9826dd19c5
  sys_init.A2                   3085160 B  feaef000b50b82a5
  system_init.A3                3085160 B  92951049f65c70d1

RESULT: PASS (41 pass, 0 fail)
EXIT=0
```

Артефакты в `/tmp/re_init2_spec/` (копии, не образы): `boot_v7.cpio`,
`boot_v7.ramdisk.gz`, `sys_init.A1`, `sys_init.A2`, `system_init.A3`,
`init.A4`, `init.from_v7`.

---

## 8. Риски и фальсификаторы

1. **Порядок веток.** Схема опирается на то, что в else-ветке `umount()` стоит
   *до* `PropertyInit()` (`0x134548` / `0x13454C`) — это видно в дизасме §1.1.
   Если `umount()` вернёт ошибку, tmpfs остаётся, и работает первая копия
   (поэтому в cpio кладутся обе).
2. **`ro.adb.secure` действительно перекрывается** последним файлом map
   (`re-init-prop-gate.md` §4.2). Если на устройстве когда-нибудь появится
   другой загрузчик prop-файлов после №13, порядок надо перепроверить.
3. **SELinux обязан быть enforcing** — но именно поэтому R4c и выбран: он не
   требует ни `exec` из ramfs, ни перемаркировки; `init` читает `rootfs`
   по уже существующему `allow` (`cil:22731`).
4. **`adb_keys` как fallback не нужен**, но если кто-то захочет его добавить:
   на user-сборке он не читается (§5.2) — не тратить на него прошивку.
5. **Не проверено на устройстве:** что `first_stage` монтирует tmpfs на
   `/debug_ramdisk` *всегда* (код `0x2F6298` безусловный в этой ветке, но сама
   ветка может зависеть от наличия debug-рамдиска). Если mount не выполняется,
   нижний слой виден сразу — маршрут всё равно работает.
6. **Проверка «а не orange ли уже»** остаётся полезной: `getprop
   ro.boot.verifiedbootstate` после первой успешной загрузки. Если orange —
   виноват был не цвет, а что-то ещё (тогда v5-рамдиск не содержал копии на
   tmpfs, потому что первая стадия не смонтировала /debug_ramdisk).
