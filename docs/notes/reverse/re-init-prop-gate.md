# Q2: property gate в `init` — почему `ro.adb.secure=0` из `adb_debug.prop` не применяется

Дата: 2026-10-25. Устройство не подключено. Всё ниже — статический разбор стоковых
бинарей из прошивки, без DA и без флеша.

Разобраны три `init`:

| бинарь | откуда | размер | sha256 | VA↔offset |
|---|---|---|---|---|
| boot-рамдиск `/init` | `docs/notes/rmx3630-lk/boot.img`, lz4-legacy @`0x1378000` | **3 143 536** | `b8088eb2b895da034ba6048a159068b5ca6f39b54d40a849e66ec33a12b907c6` | `VA = off + 0x200000` (ET_EXEC, p_vaddr 0x200000 / p_offset 0) |
| `/system/bin/init` (2-я стадия) | `IMAGES/system.img` (EROFS), извлечён параллельным агентом в `/tmp/fw/system_init` | **3 085 160** | `a458669ba60984cedf3f0491da6325e2d9f28b51f93bef8522c07308cc8c0037` | `VA = off` (ET_DYN, vaddr==offset) |
| vendor-рамдиск `system/bin/init` | `IMAGES/vendor_boot.img`, фрагмент 0 (lz4-legacy) | 2 097 128 | `de4092871407b7946fbe8c55e75577d12bdb836d911a8c279ae2490fd0d580cd` | `VA = off` (ET_DYN) |

Оговорка про оффсеты: для boot-`init` VA и файловый оффсет **не совпадают**
(разница 0x200000), для двух PIE-бинарей совпадают. В handoff'е (§2.3) все адреса
`/system/bin/init` — это VA, они же файловые оффсеты; они воспроизводятся.

Сверка с Q1 (`re-vendor-boot-q1.md`): исполняется `/init` из **boot**-рамдиска
(generic-рамдиск грузится последним и является overlay'ем), это сборка
«first-stage-only», вторая стадия — `/system/bin/init` из system.img. Настоящий
документ это использует, но не перепроверяет.

---

## 0. TL;DR (вердикт)

1. **Патч v5 (`VA 0x2F6D14`, `93 04 00 36` → `24 00 00 14`) сделан корректно** и
   действительно делает `setenv("INIT_FORCE_DEBUGGABLE","true",1)` безусловным —
   но только внутри ветки `access("/force_debuggable")==0`, т.е. маркер
   `/force_debuggable` по-прежнему обязателен (он есть в v5-рамдиске).
2. **FirstStageMain не выставляет ни одного свойства.** `ro.debuggable` /
   `ro.adb.secure` в first stage не пишутся вообще (в boot-`init` нет ни
   `SetProperty`, ни строки `ro.adb.secure`; строка `ro.debuggable` в нём
   принадлежит `__android_log_is_debuggable`, `VA 0x364AB8`).
   Переменная `INIT_FORCE_DEBUGGABLE` — единственный «мостик» в second stage.
3. **Разбор «защёлки» из handoff'а (`0x2D81A0` / `0x158C80`) — ошибка чтения.**
   `0x2D81A0` = PLT-стаб `android::base::ShouldLog()`; `0x158C80` — out-of-line
   тело `LOG(INFO) << "Loading /debug_ramdisk/adb_debug.prop"`. Это не отказ,
   а лог-ветка `if (ShouldLog(INFO))`. `0x2D87A0` = PLT `access()` — верно.
4. **Настоящий гейт находится на стадию раньше и к property-механике отношения не
   имеет.** В `SecondStageMain` (system-init `0x1342F0`) стоит:
   `getenv("INIT_FORCE_DEBUGGABLE")=="true" && fs_mgr::IsDeviceUnlocked()`, где
   `IsDeviceUnlocked()` ⇔ `androidboot/ro.boot.verifiedbootstate == "orange"`
   (libfs_mgr `0x94CD0`). Если условие ложно, `UmountDebugRamdisk()`
   (`umount("/debug_ramdisk")`) выполняется **до** `PropertyInit()`, и
   `access("/debug_ramdisk/adb_debug.prop", R_OK)` уже не срабатывает.
5. **Property-file gate (SELinux/`property_set_fd`) `ro.adb.secure` не отбивает:**
   `ro.adb.secure` = `u:object_r:build_prop:s0 exact bool`
   (`plat_property_contexts:976`), `build_prop` ∈ `property_type` (`plat_sepolicy.cil:808`),
   `(allow init property_type (property_service (set)))` (`cil:12810`), а все
   neverallow на `build_prop` исключают именно `init` (`cil:31821`:
   `base_typeattr_208 = domain ∧ ¬init`). `load_properties_from_file()` для
   `/debug_ramdisk/...` проверяет `scon = u:r:init:s0` — проходит.
6. Итог: **вердикт (d)** — не property-gate, а внешняя защёлка
   `verifiedbootstate == "orange"` (п.3/п.4). Гипотезы (b) и (c) опровергнуты
   доказательно, (a) опровергнута Q1.

---

## 1. Извлечение boot-рамдиска (deliverable)

Заголовок `docs/notes/rmx3630-lk/boot.img` — это **boot header v3/v4**
(не «v0»): `magic@0x00`, `kernel_size@0x08`, `ramdisk_size@0x0c`,
`os_version@0x10`, `header_size@0x14`, `reserved[4]@0x18`, `header_version@0x28`.
Поэтому поля, которые легко прочитать «по старой раскладке», уезжают — именно
поэтому в handoff'е родился адрес `0x137F000`.

```
$ hexdump -C -n 0x30 docs/notes/rmx3630-lk/boot.img
00000000  41 4e 44 52 4f 49 44 21  cd 6e 37 01 75 2c 19 00  |ANDROID!.n7.u,..|
00000010  89 01 00 18 30 06 00 00  00 00 00 00 00 00 00 00  |....0...........|
...
00000028  04 00 00 00                                       |....|            header_version=4
```

| поле | значение |
|---|---|
| kernel_size | 20 410 061 (0x1376ECD) |
| ramdisk_size | **1 649 781** (0x192C75) |
| header_size | 0x630 |
| header_version | 4 |
| кодек рамдиска | **lz4-legacy** (magic `02 21 4C 18` = 0x184C2102), **не gzip** |
| рамдиск @ | файловый оффсет **0x1378000** = align(0x1000+0x1376ECD, 0x1000) |

`0x137F000` из handoff'а — это `0x1378000 + 0x7000`, т.е. **внутри** lz4-потока;
gzip-магии там нет (`lz4` находил магию ровно на 0x1378000: `02214c18`).
Т.е. в handoff'е перепутаны оффсет и кодек — для стокового образа.

```
$ python3 - <<'EOF'   # (полный скрипт — в §9)
...
EOF
ramdisk_off=0x1378000 head=02214c18 len=1649781
decompressed cpio = 3 146 496 B, 15 записей
       0 040755 debug_ramdisk
       0 040755 dev
 3143536 100750 init          <-- mode 0100750
       0 040755 lib
       0 040755 lib/modules
       ...
     877 100644 system/etc/ramdisk/build.prop

$ sha256sum /tmp/initwork/ramdisk/init
b8088eb2b895da034ba6048a159068b5ca6f39b54d40a849e66ec33a12b907c6  /tmp/initwork/ramdisk/init
$ stat -c '%s %n' /tmp/initwork/ramdisk/init
3143536 /tmp/initwork/ramdisk/init
```

Размер `3 143 536` совпал с ожидаемым из задания/PLAN'а. В стоковом рамдиске
**нет** `/force_debuggable` и `/adb_debug.prop` — они добавляются только нашей
сборкой.

---

## 2. Q2.1 — проверка патча v5 и семантика FirstStageMain

### 2.1 Сайт патча

```
$ xxd -s 0xf6d10 -l 0x10 /tmp/initwork/ramdisk/init      # off 0xF6D14 = VA 0x2F6D14
000f6d10: 4804 0037 9304 0036 8000 8052 e103 1faa

$ r2 -q -c 's 0x2f6cf0; pd 12' /tmp/initwork/ramdisk/init
            0x002f6cfc      b3020052       eor w19, w21, 1
        ,=< 0x002f6d00      88250037       tbnz w8, 0, 0x2f71b0
        |   0x002f6d04      a8035d38       ldurb w8, [x29, -0x30]
       ,==< 0x002f6d08      08040037       tbnz w8, 0, 0x2f6d88
       ||   0x002f6d0c      e8434039       ldrb w8, [sp, 0x10]
      ,===< 0x002f6d10      48040037       tbnz w8, 0, 0x2f6d98
     ,====< 0x002f6d14      93040036       tbz w19, 0, 0x2f6da4   <-- САЙТ
     ||||   0x002f6d18      80008052       mov w0, 4               \  LOG(ERROR)
     ||||   0x002f6d1c      e1031faa       mov x1, xzr             /  "Failed to copy ..."
     ||||   0x002f6d20      99ab0194       bl ShouldLog(...)
     ...
     |      0x002f6da4      e0f8ff90       adrp x0, 0x212000       \  setenv("INIT_FORCE_
     |      0x002f6da8      00f40391       add x0, x0, 0xfd        /  DEBUGGABLE", "true", 1)
     |      0x002f6dac      a1f8ffd0       adrp x1, 0x20c000
     |      0x002f6db0      21d02d91       add x1, x1, 0xb74        -> VA 0x20CB74 = "true"
     |      0x002f6db4      22008052       mov w2, 1
     |      0x002f6db8      a2c20694       bl setenv
```

* `0x2F6D14`: `93 04 00 36` = `tbz w19,#0,0x2F6DA4`; `w19 = w21 ^ 1`, где `w21` —
  результат `std::__fs::filesystem::copy_file("/userdebug_plat_sepolicy.cil",
  "/debug_ramdisk/userdebug_plat_sepolicy.cil")` (`bl copy_file` @`0x2F6CE0`).
  Т.е. `w19 == 0` ⇔ копия удалась ⇔ прыжок на `setenv`.
* `0x2F6DA4..0x2F6DB8`: `setenv(name @VA 0x2120FD = "INIT_FORCE_DEBUGGABLE",
  value @VA 0x20CB74 = "true", overwrite=1)`.

Патч `24 00 00 14` = `b 0x2F6DA4`: `(0x2F6DA4-0x2F6D14)/4 = 0x24`, кодировка
`0x14000000 | 0x24 = 0x14000024` → LE `24 00 00 14`. **Семантика корректна:
setenv выполняется безусловно, если мы вообще дошли до этой точки.**
Реально изменяются **3 байта** (`93→24`, `04→00`, `36→14`; третий байт `00`
совпадает до и после) — проверено `cmp -l`: ровно 3 строки.

### 2.2 Что предшествует (граничное условие, о котором нельзя забыть)

```
0x002f6c28  adrp x0, 0x20e000 ; 0x002f6c2c  add x0, x0, 0xa89   -> "/force_debuggable"
0x002f6c30  mov w1, wzr ;        0x002f6c34  bl access               (F_OK=0)
0x002f6c38  cbnz w0, 0x2f6dbc                                    <-- нет маркера -> всё пропустить
0x002f6c50  "/adb_debug.prop"  (VA 0x2105A0)
0x002f6c6c  "/debug_ramdisk/adb_debug.prop" (VA 0x21BADB, len 0x1d)
0x002f6c90  bl copy_file                     (adb_debug.prop -> /debug_ramdisk/…)
0x002f6ca0  "/userdebug_plat_sepolicy.cil"   (VA 0x20A1B7)
0x002f6cbc  "/debug_ramdisk/userdebug_plat_sepolicy.cil" (VA 0x21BAF9, len 0x2a)
0x002f6ce0  bl copy_file                                              <-- здесь падает user-сборка
```

Итого: патч **не** делает setenv глобально безусловным — он снимает зависимость
от второй копии (`/userdebug_plat_sepolicy.cil`, которого на user-сборке нет),
но `access("/force_debuggable")` остаётся. Это ровно то, что заявлено в handoff'е
(§2.2), и это верно.

### 2.3 Что first stage делает с переменной дальше

* В boot-`init` строка `INIT_FORCE_DEBUGGABLE` встречается **один раз**
  (`0x120fd`) и имеет **единственный** xref — сам `setenv` (`0x2f6da8`).
  Проверено и `axt`, и полным сканом objdump: других `adrp/add` на `0x2120fd`
  нет. Значит **потребителя в этом бинаре нет** — он в second stage.
* Потребитель — `SecondStageMain` в `/system/bin/init` (см. §3).
* Прямого `SetProperty("ro.debuggable", ...)` в first stage **нет** (и быть не может):
  * в boot-`init` вообще отсутствует property-сервис: в дизассемблере **ноль**
    ссылок на `__system_property_add`, `__system_property_set`, `PropertySet*`
    (`grep -c` по полному `objdump -d` = 0), нет и парсера `init.rc`;
  * строки `ro.adb.secure` в boot-`init` нет вообще;
  * строка `ro.debuggable` есть (`VA 0x206FEF`), но её единственный xref —
    `class.__android_log_is_debuggable::__0` @`0x364AB8` (liblog), т.е. чтение,
    а не запись.

Единственный писатель `ro.debuggable`/`ro.adb.secure` на загрузке —
`PropertyLoadBootDefaults()` во второй стадии, из `*.prop`-файлов (§4).

---

## 3. Настоящая защёлка: `SecondStageMain` × `fs_mgr::IsDeviceUnlocked()`

`/system/bin/init`, `sym.android::init::SecondStageMain(int,char**)`
= `0x1342F0` (size 22 288):

```
0x001344a4  adrp x0, 0x1c000 ; 0x001344a8 add x0,x0,#0xf41  -> "INIT_FORCE_DEBUGGABLE" (0x1CF41)
0x001344ac  bl getenv
0x001344b0  cbz x0, 0x13453c                     ; нет env -> else-ветка
0x001344b8  bl android::fs_mgr::AvbHandle::IsDeviceUnlocked()
0x001344bc  tbz w0, #0, 0x13453c                 ; НЕ unlocked -> else-ветка
0x001344c0..0x00134504  strlen(v)==4 && std::string("true").compare(v)==0
0x00134524  bl unsetenv("INIT_FORCE_DEBUGGABLE")
0x00134528  cbnz w20, 0x134548                   ; != "true" -> else-ветка
0x0013452c  bl android::init::PropertyInit()      ; <-- /debug_ramdisk ещё СМОНТИРОВАН
0x00134530  bl android::init::UmountSecondStageRes()
0x00134534  bl android::init::UmountDebugRamdisk()
0x00134538  b  0x134554

0x0013453c  bl unsetenv("INIT_FORCE_DEBUGGABLE")  ; else-ветка
0x00134548  bl android::init::UmountDebugRamdisk()  ; <-- /debug_ramdisk снят ПЕРВЫМ
0x0013454c  bl android::init::PropertyInit()        ;     и adb_debug.prop уже не виден
0x00134550  bl android::init::UmountSecondStageRes()
```

`UmountDebugRamdisk` = `0x139A00`: `umount("/debug_ramdisk")`
(строка @`0x1BFBB`, `bl umount` @`0x139A28`).
`PropertyInit` = `0x15A430`; внутри — `mkdir("/dev/__properties__")` (`0x15A480`),
`CreateSerializedPropertyInfo()` (`0x15A484`), `__system_property_area_init`
(`0x15A488`) и **единственный** вызов `PropertyLoadBootDefaults` @`0x15AB30`.

`IsDeviceUnlocked` раскрывается в libfs_mgr (system/lib64/libfs_mgr.so):

```
AvbHandle::IsDeviceUnlocked()   0x8DCD0 : b  fs_mgr::IsDeviceUnlocked()
fs_mgr::IsDeviceUnlocked()      0x94CD0 :
    0x94ce4..0x94d1c  строит std::string(17) = "verifiedbootstate" (@0x1E2AF + 'e')
    0x94d20  bl fs_mgr_get_boot_config(key, &out)
    0x94d50  cmp len, 6 ; 0x94d70 compare(out, "orange"(@0x232F3), 6)
    0x94d78  cset w19, eq                       -> return out == "orange"
fs_mgr_get_boot_config()        0x8A840 :
    bootconfig-провайдер (0x9FDF0/0x9FED0, префикс "androidboot." @0x1B509)
    fallback: GetProperty("ro.boot." + key)  (prefix @0x23974, call @0x8A9EC)
```

Т.е. условие: `androidboot.verifiedbootstate` в kernel cmdline/bootconfig **или**
`ro.boot.verifiedbootstate` == `"orange"`. Оба значения задаёт **LK**, не наш
рамдиск. Стоковые `vbmeta*.img` имеют `flags = 0x00000000`
(проверено по `IMAGES/vbmeta.img`, `vbmeta_system.img`, `vbmeta_vendor.img` и по
встроенной `AVB0 @0x150C000` в boot.img: `flags=0`, значит бит
`VERIFICATION_DISABLED` не выставлен), поэтому нельзя априори утверждать, что LK
рапортует orange; в LK есть все четыре литерала
(`androidboot.verifiedbootstate=orange|yellow|red|` @`lk_payload 0xAC5D6/0xAC5FB/0xAC620/0xAC642`
и `oplusboot.verifiedbootstate=…` @`0x9283F…`), плюс чтение бита
`"[AVB] Fail To Get Verification Disabled Bit"` @`0xAC543`, xref `0x53CE0`.

**Вывод:** v5-patч закрывает первое слагаемое (`INIT_FORCE_DEBUGGABLE=="true"`),
но второе (`== "orange"`) не трогает — и именно оно решает, увидит ли вторая
стадия `/debug_ramdisk/adb_debug.prop`.

---

## 4. Q2.2 — собственно property-файловый гейт (и почему он не виноват)

### 4.1 Точка загрузки adb_debug.prop

`PropertyLoadBootDefaults()` = `0x156640` (size 11 152):

```
0x00156fe4  adrp x0,0x33000 ; 0x00156fe8 add x0,x0,#0x8ee  -> "/debug_ramdisk/adb_debug.prop" (0x338EE)
0x00156fec  mov w1, #4                                     ; R_OK
0x00156ff0  bl access                                      ; <-- PLT 0x2D87A0
0x00156ff4  cbnz w0, 0x157060                              ; нет файла -> пропустить
0x00156ff8  mov w0,#2 ; 0x00156ffc mov x1,xzr
0x00157000  bl android::base::ShouldLog(INFO, nullptr)      ; <-- PLT 0x2D81A0
0x00157004  tbnz w0, #0, 0x158c80                          ; <-- это ЛОГ-ВЕТКА, не отказ
0x00157008  movi v0.2d,#0 ...                              ; обнуление выходной map
0x0015700c  adrp x0,0x33000 ; add #0x8ee                   ; тот же путь
0x00157028  bl load_properties_from_file(path, nullptr, &props)   ; 0x154400
0x00157060..  обход map: PropertySetNoSocket() (0x153390) вызов @0x1570bc
              при ошибке: LOG(ERROR) "Could not set '<name>' to '<value>' while loading .prop files"
              (строки 0x157074 / 0x157084 / 0x15708C)
```

`0x158C80` — out-of-line тело `LOG(INFO)`:
`LogMessage(__FILE__ "system/core/init/property_service.cpp", 0x810, INFO) << "Loading " (@0x1B360) << "/debug_ramdisk/adb_debug.prop" (@0x338EE)`
и `b 0x157008` обратно. Никаких `return`/`skip` там нет.

**Ответ на вопрос handoff'а «не отбивает ли 0x2D81A0 загрузку»: нет.**
`0x2D81A0` — PLT-стаб `android::base::ShouldLog(LogSeverity, const char*)`
(`adrp x16,0x2e0000; ldr x17,[x16,#0x648]; br x17`), `0x2D87A0` — PLT `access`
(`[x16,#0x948]`). «Ветка 0x158C80» — лог, а не reject.

### 4.2 Порядок загрузки файлов (важно для ro.*)

`PropertyLoadBootDefaults` строит пути и вызывает `load_properties_from_file`
в таком порядке (адреса — VA вызовов):

| # | файл | вызов |
|---|---|---|
| 1 | `/system/ro.prop` (OPLUS RSC) | 0x156898 |
| 2 | `/vendor/ro.prop` (OPLUS RSC) | 0x156948 |
| 3 | `/prop.default` — **только в recovery** (`IsRecoveryMode()` 0x156B24) | 0x156B48 |
| 4 | `/second_stage_resources/system/etc/ramdisk/build.prop` (`access()` 0x156C14) | 0x156D14 |
| 5 | `/system/build.prop` | 0x156D78 |
| 6 | `/system/euclid_build.prop` | 0x156E08 |
| 7 | `/vendor/default.prop` | 0x156E40 |
| 8 | `/vendor/build.prop` | 0x156E78 |
| 9 | `/vendor_dlkm/etc/build.prop` | 0x156EB0 |
| 10 | `/vendor/euclid_build.prop` | 0x156EE8 |
| 11 | `/odm_dlkm/etc/build.prop` | 0x156F20 |
| 12 | product / system_ext / odm (лямбды `PropertyLoadBootDefaults::__4`) | 0x156F70, 0x156FB4 |
| 13 | **`/debug_ramdisk/adb_debug.prop`** | 0x157028 |

Все файлы сваливаются в один `std::map<string,string>`, а **применяются один раз
в конце** (цикл `0x157060`, `PropertySetNoSocket` @`0x1570BC`). Дубликаты при
вставке перекрываются с явным логом
`"Overriding previous property '<name>': '<old>' with new value '<new>'"`
(`0x155328`/`0x15536C`) — значит `adb_debug.prop` (последний) **перекрывает**
`/system/build.prop` в map, и `Read-only property was already set` (код 11) на
нём **не срабатывает**.

Это же объясняет, почему пропатченный в v5 `system/etc/ramdisk/build.prop`
«бесполезен»: его грузят **пунктом 4**, т.е. до `/system/build.prop` (п.5), и
`ro.adb.secure=1` из system перекрывает наше `0`. (Плюс сам файл в rootfs
накрывается монтированием `/system` — путь читается только через
`/second_stage_resources/...`.)

### 4.3 Где свойство может быть отброшено

`load_properties_from_file()` = `0x154400` (4328 B). Для каждого распарсенного
`name=value`:

```
0x00154e64  bl android::init::CheckPermissions(name, value, scon, ucred, &err)   ; 0x152260
0x00154e84  cbz w26, 0x154fac            ; 0 == OK -> положить в map
0x00154e88  LOG(ERROR) "Do not have permissions to set '<name>' to '<value>' in property file '<file>': <err>"
```

`scon` выбирается по префиксу имени файла:
`/vendor`, `/odm`, `/vendor_dlkm`, `/odm_dlkm` → `"u:r:vendor_init:s0"` (0x1547D8),
иначе → **`"u:r:init:s0"`** (0x154734/0x1547E8). Для
`/debug_ramdisk/adb_debug.prop` → `u:r:init:s0`.

`CheckPermissions()` = `0x152260` (708 B):

1. `IsLegalPropertyName()` (0x15229C) — иначе `"Illegal property name"`, код 0x10;
2. `StartsWith(name,"ctl.")` (0x1522AC) → `CheckControlPropertyPerms()` (0x1522E4);
3. иначе: `PropertyInfoArea::GetPropertyInfo(area @[0x2e3558], name, &context, &type)`
   (0x152330) — это **сериализованный property_info**, построенный ранее
   `CreateSerializedPropertyInfo()` (`0x159D00`, вызывается из `PropertyInit`
   @0x15A484) из `/system/etc/selinux/plat_property_contexts` (0x2C100),
   `/plat_property_contexts` (0x18A16), `/vendor/...`, `/nonplat_*` — т.е.
   **да, используется plat_property_contexts-модель**, но уже в скомпилированном
   виде, а не чтением файла в этот момент;
4. `context==nullptr || scon==nullptr` → `"SELinux permission check failed"` (код 0x18);
5. `selinux_check_access(scon, context, "property_service", "set", audit)` (0x152378)
   → != 0 → `"SELinux permission check failed"` (код 0x18; для ctl. —
   `"Invalid permissions to perform '%s' on '%s'"`).

Затем, уже при применении map: `PropertySet()` = `0x153440`:

```
0x1535d8  __system_property_find(name)
0x1535f8  cbz -> 0x15362c: __system_property_add(...)      ; создание
0x153608  StartsWith(name,"ro." @0x2D997)
0x153614  assign "Read-only property was already set" (0x2B298)
0x153624  mov w8/w9 = 0xb -> return 11
иначе     обновление существующего
```

**Условия отбрасывания (полный список):**
| условие | сообщение | когда применимо к `ro.adb.secure=0` |
|---|---|---|
| нелегальное имя | `Illegal property name` | нет |
| `ctl.*` без прав | `Invalid permissions to perform 'set' on '<file>'` | нет |
| нет контекста в property_info / SELinux deny | `SELinux permission check failed` → `Do not have permissions to set ... in ... property file` | **нет** (см. §4.4) |
| свойство уже в property area и начинается на `ro.` | `Read-only property was already set` (код 11) → `Could not set ... while loading .prop files` | **нет**: map применяется один раз после всех файлов, `adb_debug.prop` последний и перекрывает `system/build.prop` в map |
| файл не открылся | `access()` != 0 → тихий skip | **да, если /debug_ramdisk уже размонтирован (§3)** |

### 4.4 SELinux: `ro.adb.secure` init'у разрешён

```
system/etc/selinux/plat_property_contexts:
  947: ro.debuggable       u:object_r:userdebug_or_eng_prop:s0 exact bool
  948: ro.force.debuggable u:object_r:build_prop:s0           exact bool
  976: ro.adb.secure       u:object_r:build_prop:s0           exact bool

plat_sepolicy.cil:
  808: (typeattributeset property_type (... build_prop ... userdebug_or_eng_prop ...))
12810: (allow init property_type (property_service (set)))
31821: (typeattributeset base_typeattr_208 (and (domain ) (not (init ))))
 8417: (neverallow base_typeattr_208 build_prop (property_service (set)))
 8422: (neverallow base_typeattr_208 userdebug_or_eng_prop (property_service (set)))
```

`neverallow` исключает `init` — значит `init` сеттить `build_prop`
**разрешено** (`allow init property_type set`). Тип значения `exact bool`,
`"0"` — валидный bool. Т.е. `ro.adb.secure=0` из adb_debug.prop контекстом
**не отбивается**.

Косвенное подтверждение: `ro.adb.secure=1` на стоке выставляется тем же
механизмом из `/system/build.prop` (`/system/build.prop:119-125`), т.е. через
`init` + `build_prop`.

---

## 5. Вердикт по Q2.3 и что наблюдать на устройстве

**Вердикт: (d), «другое».** Не property-gate. Порядок причин:

1. `(a)` **опровергнута** (`re-vendor-boot-q1.md` §6-§7: generic-рамдиск
   грузится последним → PID 1 = boot-рамдискный `/init` 3 143 536 B, патч v5
   попадает в исполняемый бинарь).
2. `(b)` **опровергнута**: контекст `build_prop` + `allow init property_type set`
   (§4.4); «ветка 0x158C80» — лог (§4.1); `ro.*`-read-only не срабатывает из-за
   однократного применения map (§4.2/§4.3).
3. `(c)` **не причина**: adbd читает `ro.adb.secure` из той же property area
   (`GetBoolProperty("ro.adb.secure", …)` при старте adbd), других источников у
   флага нет; и при `ro.adb.secure=0` adbd авторизует без ключа независимо от
   `adb_keys`.
4. `(d)` **остаётся и объясняет симптом полностью**: вторая стадия снимает
   `/debug_ramdisk` **до** `PropertyInit()`, если
   `getenv("INIT_FORCE_DEBUGGABLE") != "true"` **или**
   `fs_mgr::IsDeviceUnlocked()` ложно (⇔ `verifiedbootstate != "orange"`).
   v5 закрыл только первое слагаемое. Тихий `access()!=0` → `cbnz` → свойства не
   грузятся вообще, никакой ошибки в лог не пишется — ровно наблюдаемая картина
   (`ro.adb.secure` = 1 из `/system/build.prop`).

**Что различит остаток гипотез (на устройстве):**

```bash
getprop ro.boot.verifiedbootstate   # "orange" -> гейт пройден; иначе (green/yellow) -> причина найдена
getprop ro.boot.vbmeta.device_state # unlocked/locked
getprop ro.debuggable               # 1 = adb_debug.prop всё-таки загрузился
getprop ro.adb.secure
ls -l /init ; sha256sum /init       # b8088eb2… = boot-рамдиск исполняется (Q1)
dmesg | grep -i 'debug_ramdisk\|verifiedboot'
```
Если `verifiedbootstate == orange` — гейт §3 пройден, и тогда единственный
оставшийся кандидат — то, что env не дошёл до второй стадии (проверять
`/proc/<pid1>/environ` или добавить маркер в first stage).

Без root/adb: единственный offline-совместимый маркер — записать из first stage
строку в `/metadata` (раздел дампится через DA) либо собрать v6 с маркером
`/v6_marker` (см. `re-vendor-boot-q1.md` §8) и проверить readback'ом.

---

## 6. Q2.4 — спека патча

### P1 — v5 (уже прошит; проверено, что корректен)

| | |
|---|---|
| бинарь | boot-рамдиск `/init` (3 143 536 B, sha256 `b8088eb2…`) |
| VA / файловый оффсет | `0x2F6D14` / `0xF6D14` |
| было | `93 04 00 36` = `tbz w19,#0,0x2F6DA4` |
| стало | `24 00 00 14` = `b 0x2F6DA4` (расходятся 3 байта: +0, +1, +3) |
| смысл | `setenv("INIT_FORCE_DEBUGGABLE","true",1)` без требования копии `/userdebug_plat_sepolicy.cil`; `access("/force_debuggable")` остаётся |
| эффект | необходимая, но **не достаточная** половина: снимает слагаемое №1 гейта §3 |

### P2 — кандидат v6 (только если Q1 §8-verification покажет симлинк `/init`)

| | |
|---|---|
| бинарь | vendor-рамдиск `system/bin/init` (2 097 128 B, sha256 `de409287…`) |
| VA / файловый оффсет | `0x0F1710` / `0x0F1710` |
| было | `33 05 00 36` = `tbz w19,#0,0xF17B4` (расходятся 3 байта) |
| стало | `29 00 00 14` = `b 0xF17B4` (`(0xF17B4-0xF1710)/4 = 0x29`) |
| смысл | точный аналог P1 в другой сборке (`setenv` @`0xF17B4`, значение `"true"` @`0x1AAAA`) |
| эффект | тот же — снимает только слагаемое №1 |

### Что P1/P2 **не** лечат и что нужно для слагаемого №2

`verifiedbootstate` приходит из LK (cmdline/bootconfig), поэтому:

* **вариант L1 (предпочтительный, если цвет ≠ orange):** добавить/переопределить
  `androidboot.verifiedbootstate=orange` в cmdline, который отдаёт LK
  (boot.img `cmdline@0x30` пуст; порядок «наш cmdline vs LK» надо проверить —
  для `ro.boot.*` действует first-wins, а `fs_mgr_get_boot_config` читает
  bootconfig/cmdline напрямую);
* **вариант L2:** правка второго stage (`/system/bin/init`, EROFS) — недоступно
  без RW system;
* **вариант L3 (hack):** сделать `/debug_ramdisk` busy на момент
  `UmountDebugRamdisk()` (открытый без `O_CLOEXEC` fd / вложенный bind) —
  требует инъекции кода в first stage, не 4-байтовый патч.

Т.е. **честный вывод: 4-байтовым патчем init проблему `ro.adb.secure` не
закрыть, если LK рапортует не `orange`.** Сначала измеряем
`ro.boot.verifiedbootstate`.

---

## 7. Валидация спеки (deliverable)

`docs/notes/init_patch_spec_test.py` применяет P1 и P2 к **копиям** в
`/tmp/init_patch_test/`, проверяет: стоковые байты, ровно 4 отличающихся байта
по ожидаемым оффсетам, совпадение остального файла, парсинг ELF (e_type,
e_entry, размер, число секций), декодирование ветки в ожидаемую цель, и (если
есть `r2`) — что дизасм показывает `b <target>`.

```
$ python3 docs/notes/init_patch_spec_test.py
SPEC  boot-ramdisk /init (v5, first stage)
      src    /tmp/initwork/ramdisk/init (3143536 B)
      sha256 b8088eb2b895da034ba6048a159068b5ca6f39b54d40a849e66ec33a12b907c6
      VA 0x2f6d14 -> file offset 0xf6d14
      wrote  /tmp/init_patch_test/ramdisk_init.patched
PASS  diff is exactly 3 byte(s) at ['0xf6d14', '0xf6d15', '0xf6d17'] (instruction at 0xf6d14..0xf6d17)
PASS  ELF parses: e_type=2 e_machine=183 e_entry=0x2ed000 phnum=10 shnum=18
PASS  93040036 -> b 0x2f6da4
      r2: 0x002f6d14      24000014       b 0x2f6da4
PASS  boot-ramdisk /init (v5, first stage): 0xf6d14 93040036 -> 24000014 (b 0x2f6da4, 3 byte(s) changed)

SPEC  vendor-ramdisk system/bin/init (v6 candidate)
      src    /tmp/fw/init_vendor (2097128 B)
      sha256 de4092871407b7946fbe8c55e75577d12bdb836d911a8c279ae2490fd0d580cd
      VA 0xf1710 -> file offset 0xf1710
      wrote  /tmp/init_patch_test/fw_init_vendor.patched
PASS  diff is exactly 3 byte(s) at ['0xf1710', '0xf1711', '0xf1713'] (instruction at 0xf1710..0xf1713)
PASS  ELF parses: e_type=3 e_machine=183 e_entry=0xb1000 phnum=11 shnum=29
PASS  33050036 -> b 0xf17b4
      r2: 0x000f1710      29000014       b 0xf17b4
PASS  vendor-ramdisk system/bin/init (v6 candidate): 0xf1710 33050036 -> 29000014 (b 0xf17b4, 3 byte(s) changed)

RESULT: PASS (2/2 specs)  exit=0

$ cmp -l /tmp/initwork/ramdisk/init /tmp/init_patch_test/ramdisk_init.patched
1010965 223  44
1010966   4   0
1010968  66  24
$ readelf -h /tmp/init_patch_test/ramdisk_init.patched | head -6
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
```

---

## 8. Правки к предыдущим документам

1. Termux-handoff от 2026-10-25 (удалён), §2.3: `0x2D81A0` — не «неопознанный вызов,
   который может отбить», а PLT `android::base::ShouldLog`; `0x158C80` — не
   «ветка нет прав», а тело `LOG(INFO) "Loading /debug_ramdisk/adb_debug.prop"`.
2. Там же: «`/prop.default` читается только после `IsRecoveryMode()`» — верно,
   но добавляем: `system/etc/ramdisk/build.prop` читается как
   `/second_stage_resources/system/etc/ramdisk/build.prop` **до**
   `/system/build.prop`, поэтому пропатченный в v5 файл перекрывается.
3. `PLAN`/handoff: рамдиск стока — **lz4-legacy** @`0x1378000`, не gzip
   @`0x137F000` (0x137F000 — внутри lz4-потока).
4. Новое (не было ни в одном документе): гейт `verifiedbootstate=="orange"`
   в `SecondStageMain` — см. §3.

---

## 9. Воспроизведение

```bash
# 1) рамдиск
python3 - <<'EOF'
import struct, gzip
d=open('docs/notes/rmx3630-lk/boot.img','rb'); assert d.read(8)==b'ANDROID!'
ks,rs = struct.unpack('<2I', d.read(8))
d.seek(0x1378000); open('/tmp/initwork/ramdisk.lz4','wb').write(d.read(rs))
EOF
lz4 -d -f /tmp/initwork/ramdisk.lz4 /tmp/initwork/ramdisk.cpio   # newc, 3 146 496 B
# распаковка cpio — см. лог §1; /init = 3 143 536 B

# 2) патч-сайт
r2 -q -c 's 0x2f6cf0; pd 24' /tmp/initwork/ramdisk/init
r2 -q -c 's 0x2f6da4; pd 6'  /tmp/initwork/ramdisk/init

# 3) xrefs
r2 -q -c 'aaa; s 0x21badb; axt' /tmp/initwork/ramdisk/init   # /debug_ramdisk/adb_debug.prop
r2 -q -c 'aaa; s 0x2120fd; axt' /tmp/initwork/ramdisk/init   # INIT_FORCE_DEBUGGABLE

# 4) вторая стадия
r2 -q -c 'aaa; afi @ 0x1344a4; afi @ 0x156fe4; afi @ 0x152260; afi @ 0x153614' /tmp/fw/system_init
r2 -q -c 's 0x94cd0; pd 62' /tmp/fw/sysroot/system/lib64/libfs_mgr.so

# 5) селinux-факты
grep -nE '^(ro\.adb\.secure|ro\.debuggable)' /tmp/fw/sysroot/system/etc/selinux/plat_property_contexts
grep -nE 'allow init property_type \(property_service' /tmp/fw/sysroot/system/etc/selinux/plat_sepolicy.cil

# 6) спека патча
python3 docs/notes/init_patch_spec_test.py
```

## 10. Оговорки

* `/system/bin/init` (3 085 160 B) взят из `/tmp/fw/system_init` — распаковка
  system.img (884 MB sparse → EROFS) выполнена **параллельным агентом (Q3)**;
  sha256 зафиксирован в таблице. Если hash не совпадёт с вашей распаковкой —
  все VA во второй стадии надо перепроверить (для PIE-бинаря VA==offset, так что
  сверять надо именно hash, а не оффсеты).
* Ветка `verifiedbootstate` в LK статически **не** разрешена до конца: в
  `lk_payload.bin` найдены все четыре литерала цвета и чтение бита
  `VERIFICATION_DISABLED`, но прямая кодовая ссылка на литералы не находится
  (строки живут в таблице, собираемой LK в рантайме) — поэтому цвет на устройстве
  надо измерить, а не предсказать.
* `vendor_boot` не содержит bootconfig (`bootconfig_size = 0`), `boot.img` cmdline
  пуст → `androidboot.*` целиком формирует LK.
