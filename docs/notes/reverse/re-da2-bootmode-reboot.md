# RE: DA2 CMD:SET-BOOT-MODE (0x40005d84) и CMD:REBOOT (0x40005ba8) — полные карты, судьба boot-mode, почему reboot уходит в NORMAL

Date: 2026-10-24. Binary: `/home/musin/firmware/extracted/IMAGES/da2_oplus.bin` (356296 B),
ARM32, **VA = file offset + 0x40000000** (все адреса ниже — VA).
Инструмент: capstone-скрипт `/tmp/opencode/da2/da2dis.py` (линейный дизасм + резолв
pc-relative литералов), байтовые sweep'и movw/movt/BL на xrefs. Компаньоны:
`re-lk-bootmode-priority.md`, `re-preloader-bootmode-atag.md`, `re-lk-rescue-surfaces.md`,
`re-lk-seccfg.md`, `re-sec-dispatch.md`, `re-heapbait-vuln.md`.

Статусы: **[proven]** = инструкция/байты прочитаны и приведены; **[inferred]** = помечено
уровнем уверенности.

---

## TL;DR

1. **SET-BOOT-MODE FASTBOOT [proven]: единственный эффект — запись ниббля 3 в RGU-регистр
   `0x10007024`** (0x4002a4c8: `ldr r1,[r0]` / `bfi r1,r2,#0,#4` при r2=3 / `str`).
   Никаких записей в proinfo, RPMB, разделы, shared-SRAM с preloader на этой ветке нет.
2. **META / ANDROID-TEST-MODE пишут во flash**: META — флаги adb/mobile_log + enum
   com-типа в record раздела **proinfo** (через ops-таблицу 0x40054374 read 0x400 B +
   write обратно), ATM — десятичная ASCII-строка в proinfo. Обе ветки — flash-state,
   но **LK этого билда boot_mode из proinfo не потребляет** [proven по
   re-lk-bootmode-priority §1.2 — в приоритет-цепочке proinfo отсутствует].
3. **CMD:REBOOT — это DPC-отложенный вызов**: хендлер только кладёт `dpc->cb` в структуру
   0x40069dec и возвращает OK; исполнение — на следующей итерации cmd_loop (blx @0x40008c28).
   action=IMMEDIATE/WARM-RESET → 0x40031420 = **WDT SW-reset**; при этом подготовка
   (0x4002a4e4) делает `bic 0xff0` по 0x10007024 — **биты [3:0] (наш ниббл) она НЕ трогает**
   [proven]. EDL-ветка отдельно ORR'ит 0xE в тот же регистр.
4. **Статически цепочка «SET-BOOT-MODE FASTBOOT → REBOOT IMMEDIATE → LK читает ниббл 3 →
   0x63 FASTBOOT» выглядит рабочей** (preloader в 0x10007024 не пишет — proven-by-absence;
   LK ниббл 3 → FASTBOOT — proven). Наблюдаемый NORMAL означает, что ниббл теряется между
   WDT-резетом и LK — точка потери не локализована (BROM не разобран; preloader-clean
   по sweep'у). Дешёвый тест: `CMD:WRITE-REGISTER` 0x10007024 |= 3 + `CMD:REBOOT IMMEDIATE`
   и контроль значения на следующей DA-сессии + UART `boot_mode_check:g_boot_mode is set %u`.
5. Рабочих путей DA2→«LK fastboot» из flash (misc BCB «boot-fastboot» — не читается LK;
   proinfo — не потребляется; RPMB boot-info из DA2 не пишется) **кроме RGU-ниббля нет**;
   RGU-ниббль — единственный кандидат, статус «не доказан на живом устройстве».

---

## 1. CMD:SET-BOOT-MODE handler 0x40005d84 — полная карта

Регистрация: строка `CMD:SET-BOOT-MODE` @0x400415f3 → handler 0x40005d84 (таблица
регистрации в re-sec-dispatch.md §2.3 — подтверждено). XML-узлы (байты прочитаны):
`da/arg/mode` 0x40042624, значения `META` 0x40042630, `FASTBOOT` 0x40042669,
`ANDROID-TEST-MODE` 0x40042672, `da/arg/connect_type` 0x40042635 (`USB` 0x400419c3 /
`UART` 0x400419c7), `da/arg/mobile_log` 0x40042649 / `da/arg/adb` 0x4004265b
(`ON` 0x40042666). Соответствует mtkclient `cmd_set_boot_mode` (xml_cmd.py:358).

```
0x40005d84  push {r4-r8,sl,fp,lr}; r4 = xml (r1)
0x40005d90  bl 0x40008468                     ; [inferred] protocol/session state setter
0x40005da4  bl 0x4000d0bc                     ; mxml_load_string(xml)  [proven по re-heapbait-vuln §1]
            fail -> 0x40005e2c: log через [0x40054314] (0x400084a4), err 0xC0010001
0x40005dbc  bl 0x40001e48                     ; get_node "da/arg/mode"; fail -> err 0xC0010001 (0x40005ed4)
0x40005dd8  bl 0x4000b5e0(r0=mode, "META", 5) ; cmp helper
            ==0 -> 0x40005e40  META-ветка (§2)
0x40005df4  bl 0x4000b5e0(mode, "FASTBOOT", 0xf)
            ==0 -> 0x40005ef8  FASTBOOT-ветка (§1.1)
0x40005e10  bl 0x4000b5e0(mode, "ANDROID-TEST-MODE", 0x12)
            ==0 -> 0x40005f04  ATM-ветка (§3)
            else -> err 0xC0010003 (0x40005e24: r5 = 0xC0010001|2)
```

### 1.1 FASTBOOT-ветка (0x40005ef8 → 0x40031500 → 0x4002a4c8) — [proven]

```
0x40005ef8  bl 0x40031500
0x40031500  b  0x4002a4c8                     ; единственный xref (BL-sweep: только сюда)
0x4002a4c8  movw r0,#0x7024; movt r0,#0x1000  ; r0 = 0x10007024
0x4002a4d0  mov  r2,#3
0x4002a4d4  ldr  r1,[r0]
0x4002a4d8  bfi  r1,r2,#0,#4                  ; bits[3:0] = 3
0x4002a4dc  str  r1,[r0]
0x4002a4e0  bx  lr                            ; ret 0 -> 0x40005efc: r5=0 -> OK
```

Запись: **только 4 бита в 0x10007024**. Не пишет: proinfo (нет вызова 0x40012e9c),
RPMB (нет rpmb-вызовов), разделы (нет blx 0x40054374+4), SRAM-preloader (нет записей в
0x2F4xxx-диапазон, которого в DA2 вообще нет). Побочные логи — отсутствуют.

Соседний хелпер **0x4002a520** (тот же регистр, не вызывается из этой ветки):
`ldr r2,[0x10007024]; bic r2,#0xff0; orr r0,r2,r0,lsl#4; str` — writer произвольного
ниббля (r0<<4) с сохранением остального. Xrefs не искал отдельно; это тот же
«nibble-setter» класс, что 0x5004058C в LK [inferred: общий MTK-драйвер reboot-arg].

### 1.2 Константы FASTBOOT-ниббля vs LK

LK `boot_mode_check` (re-lk-bootmode-priority §1.2, proven): ниббль 3 → mode 0x63
FASTBOOT; 2 → RECOVERY; 0xC → agingtest; 0xA → 0xC; 0xB → pass-through. DA2 пишет ровно
значение 3 — попадает в ветку FASTBOOT LK, **если доживёт** (см. §5).

## 2. META-ветка: 0x40005e40 → 0x4000c8e0 — флаги в proinfo [proven]

Разбор узлов: `connect_type` (0x40005e4c), `mobile_log` (0x40005e68), `adb`
(0x40005e84); любой отсутствует → err 0xC0010001 + mxml free (0x4000ea94).

```
0x40005e9c-0x40005ecc: connect_type cmp "USB"(5) -> r7=1 (0x40005f0c);
                       else cmp "UART"(4): r7=3 default, ==UART -> r7=2 (0x40005ecc)
0x40005f10-0x40005f44: mobile_log/adb cmp "ON"(3) -> clz-bools (r1=mobile_log, r2=adb)
0x40005f48  mov r0,r7; bl 0x4000c8e0(mode_enum, mobile_log, adb)
```

fcn.4000c8e0 (604 B):

```
0x4000c8e8  sub sp,#0x68; r8 = sp+0x10 (0x58-байтный local)
0x4000c908  memset(r8, 0, 0x58)
0x4000c910  cmp mode,0 ; movwne r4,#1          ; mode!=0 -> r4=1
0x4000c918  cmp adb,0  ; movwne r7,#1
0x4000c928  bl 0x40012e9c("proinfo" 0x40043ebd) ; partition-entry lookup (§2.1)
            fail -> "find partition info from partition table failed. status: 0x%x" (0x40043ec5)
0x4000c958  mov r0,#0x400; bl 0x4000a59c        ; malloc(0x400)
0x4000c96c  orr r7,r7,r4,lsl#1                  ; flags = adb | mobile_log<<1
0x4000c97c  ldr r3,[0x40054374+0]; blx r3       ; READ 0x400 B записи proinfo
            ;   r0/r1 = [sp+0x58]/[sp+0x5c] = u64 offset записи (заполнен lookup'ом),
            ;   r2=buf, r3=0, [sp]=0x400 (len), sp+4=0, sp+8=&record
0x4000c9a0  strb r7,[r5,#0x154]                 ; buf+0x154 = flags (adb bit0, mobile_log bit1)
0x4000c9a4  strb mode,[r5,#0x153]               ; buf+0x153 = mode enum (1=USB,2=UART,3=проч.)
0x4000c9a8  strb 1,[r5,#0x152]                  ; buf+0x152 = 1 (valid-маркер, inferred)
0x4000c9ac-0x4000ca00: логи "mtk_boot_mode_flag.boot_mode=%d" (0x40043f04),
            ".com_type=%d" (0x40043f25), ".com_id=%d" (0x40043f45) — печатаются значения
            ИЗ ПРОЧИТАННОЙ записи (buf+0x152/0x153/+0x48-область), а не аргументов
0x4000ca04  ldrd r0,r1,[r8,#0x48]               ; u64 offset записи
0x4000ca0c  ldr r3,[0x40054374+4]; blx r3       ; WRITE 0x400 B обратно (len [sp]=0x400)
0x4000ca28  free(buf) -> ret
```

**Куда пишется mode [proven]:** раздел **proinfo**, в найденную запись (0x58-байтная
структура в таблице записей 0x4006A95C; поиск по имени через 0x40012e9c, таблица
`[0x4006A95C+4]=count, +8=entries, запись+8 = имя[0x40], stride 0x58`), байты
**record+0x152 (valid=1), +0x153 (boot_mode enum), +0x154 (flags adb/mobile_log)**,
смещение записи берётся из `record+0x48` (u64). Это oplus-«mtk_boot_mode_flag»-механизм
(строки-логи прямо так называются). RPMB/разделы/ATAG — не затрагиваются.

### 2.1 0x40012e9c — lookup записи «proinfo» [proven механика]

Две таблицы: `[0x4006A95C+4]/[+8]` (основная) и `[0x4006A968+4]/[+8]` (вторичная,
+запись при отсутствии: append-путь 0x40012f64 — добавляет новую запись с именем).
Сравнение имени — 0x4000b5e0 (strncmp, 0x40). Не найдено в обеих и loglevel≤2 →
`[%s] …` лог (0x40045e7e) и err 0xC0040006.

### 2.2 Потребление proinfo-флага downstream

LK этого билда **не читает** proinfo boot-mode в `boot_mode_check` (приоритет-цепочка
re-lk-bootmode-priority §1.2: ATAG → HW-ниббль → misc BCB → rc_wdt → HW-3 → reason →
default; proinfo нет) — [proven по списку читателей misc/резервов]. META-механика LK
(`atag,meta`-парсинг, meta_init.rc-кмдлайн, adb/elt-флаги 0x5011329C) питается
исключительно ATAG'ами preloader'а (re-lk-rescue-surfaces §3). ⇒ **META-запись из DA2
на этом юните downstream-эффекта не имеет** [inferred, high].

## 3. ANDROID-TEST-MODE-ветка: 0x40005f04 → 0x4000ca48 [proven механика, семантика частично]

```
0x4000ca48  memset 0x58-записи; bl 0x40012e9c("proinfo")  ; та же lookup-машина
            fail -> "find partition info … failed"
0x4000cab8  snprintf(sp+0x10, 9, fmt 0x40043f63="%d", r3=0x1DC92BC)  ; vsnprintf-thunk 0x4000a638
            ; [inferred] r3 — «шифрованный» счётчик/значение atm (ciper_text fmt 0x40043f60 рядом)
0x4000cafc  ldr r1,[sp+0x6c]; ldr r3,[0x40054374+4]; blx r3      ; WRITE: offset=[sp+0x68]+0x15E,
            ; len [sp]=8, buf=sp+0x10  -> 8-байтная ASCII-строка "%d" в proinfo (off+0x15E)
```
Соседняя строка `set_atm_mode` 0x40043f79 в регионе — ATM-запись. Для основного вопроса
не критична: тоже flash (proinfo), LK-консьюмера в boot_mode_check нет [proven по §1.2
приоритетов].

## 4. CMD:REBOOT handler 0x40005ba8 — полная карта [proven]

Строка `CMD:REBOOT` 0x40041583 → 0x40005ba8. XML-узел `da/arg/action` 0x4004249b
(= строка «reboot» 0x400424a9, совпадение с memcmp(…,"reboot",7) в cmd_loop 0x40008c44).
Действия mtkclient: `cmd_reboot(disconnect=False)` → `<action>IMMEDIATE</action>`
(xml_cmd.py:429-436); `shutdown(FASTBOOT)` = SET-BOOT-MODE(FASTBOOT) + REBOOT(IMMEDIATE)
(xml_lib.py:1655-1666) — ровно наблюдаемая последовательность.

```
0x40005ba8  push {r4,r5,fp,lr}; r4=xml
0x40005bc8  bl 0x4000d0bc                       ; mxml_load_string; fail -> err
0x40005be0  bl 0x40001e48                       ; get_node "da/arg/action"; fail -> err (+mxml free)
0x40005bf0  bl 0x4002a91c -> b 0x4001fb3c       ; [inferred] flush/commit перед постановкой DPC
                                                ;   (внутри — bl 0x4001eae8-стиль вызов + mdelay(0x64))
0x40005bf4  r5 = 0x40069dec                     ; DPC-структура (re-heapbait-vuln §1)
0x40005c0c  str 0x400424a9,[r5]                 ; dpc->name = "reboot"
0x40005c18  str r4,[r5,#8]                      ; dpc->arg   = указатель на значение узла
0x40005c1c  bl 0x4000b5e0(action,"OPLUS_DELAY_REBOOT",0x12) ==0 -> 0x40005d04:
                dpc->cb = 0x4003143c  (DELAY, §4.1); лог "[OPLUS]oplus_dev_wdt_reset"; ret 0
0x40005c34  cmp "OPLUS_REBOOT_TO_EDL"(0x13) ==0 -> 0x40005d40:
                dpc->cb = 0x400314a8  (EDL, §4.2); лог "[OPLUS] oplus_set_reboot_edl"; ret 0
0x40005c50  cmp "IMMEDIATE"(0xa) ==0 -> 0x40005d2c:
                dpc->cb = 0x40031420  (WDT SW-reset, §4.3); ret 0
0x40005c6c  cmp "WARM-RESET"(0xb) ==0 -> 0x40005d2c: тот же cb 0x40031420; ret 0
0x40005c88  cmp "COLD-RESET"(0xb) ==0 -> 0x40005d6c:
                dpc->cb = 0x4002a908 -> b 0x4001f54c (§4.4); ret 0
0x40005ca4  cmp "DISCONNECT"(0xb) ==0 -> 0x40005d78:
                dpc->cb = 0x40031394 (§4.5); ret 0
else -> "Unknown reboot action: %s" (0x4004253c) -> err 0xC0010001
```

### 4.1 DELAY: cb = 0x4003143c [proven]

```
0x4003143c  лог "Delay rebooot after update ufs firmware" (0x4004f772)
0x40031460  bl 0x4002a4e4                       ; RGU-подготовка (§4.3-ядро): bic 0xff0 в 0x10007024
0x40031470  лог "WDT_HW_Reset_test" (0x4004f79b)
0x4003147c  r0=3; bl 0x4002a710                 ; 0x10007004 = (3<<11)|8  (WDT TIMEOUT, [inferred])
0x4003149c  bl 0x4002a660                       ; RGU config (0x2a53c + 0x10007000 |= 0x22000000-стиль)
0x400314a0  bl 0x4002a728                       ; 0x10007008 = 0x1971 (WDT restart-ключ)
0x400314a4  b .                                 ; спин до срабатывания WDT
```
Задержанный **HW**-watchdog reset (timeout-поле 3). Ниббль 0x10007024 — не трогается
(bic 0xff0 биты[3:0] сохраняет).

### 4.2 EDL: cb = 0x400314a8 [proven]

```
0x400314bc  лог "WDT_HW_Reset_test" (0x4004f79b)
0x400314c8  bl 0x4002a5e8: 0x10007024 |= 0xE    ; bits[1..3] = 1  -> ниббль |= 0xE (при 3 -> 0xF)
0x400314d8+ лог/второй сетап; r0=3 → 0x4002a710 (0x10007004=(3<<11)|8);
            0x4002a660 (RGU config); 0x4002a728 (0x10007008=0x1971); спин
```
«Reboot to EDL» реализован как **н Marl-маркер в RGU-регистре** (orr 0xE), консьюмер —
BROM/preloader (не LK; LK таких нибблей не обрабатывает: 0xF не входит в {2,3,0xC,0xA,0xB}
— [proven] по приоритет-таблице).

### 4.3 IMMEDIATE / WARM-RESET: cb = 0x40031420 [proven]

```
0x40031420  bl 0x4002a4e4:
    0x4002a4ec  r4 = 0x10007024
    0x4002a4f4  ldr r0,[r4]; bic r0,#0xff0; str     ; очистить bits[4..11], биты[3:0] СОХРАНЯЮТСЯ
    0x4002a500  str 0,[r4,#-4]                      ; 0x10007020 = 0
    0x4002a508  bl 0x4002a53c                       ; RGU mode-config (0x10007000, 0x2300 1FF-стиль,
                                                    ;   ветвление по биту 0x20, 0x22000000)
    0x4002a50c  ldr r0,[r4]; mov r1,#4; bfi r0,r1,#0x1d,#3; str   ; bits[31:29]=4 (SW-reset тип)
0x40031428  bl 0x4002a5c0:
    0x4002a5c8  bl 0x4002a53c
    0x4002a5cc  0x10007000 |= 1 | 0x22000000        ; WDT enable + reset-request биты [inferred naming]
0x4003142c  bl 0x4002a728: 0x10007008 = 0x1971      ; WDT kick
0x40031434  pop → возврат в cmd_loop (система падает в reset по WDT через миллисекунды)
```

### 4.4 COLD-RESET: cb = 0x4002a908 → b 0x4001f54c [механика proven, семантика inferred]

`mov r0,#0xa08; mov r1,#1; mov r2,#1; mov r3,#8; b 0x4001eae8` — 0x4001eae8 — общий
обёрточный вызов (внутри 0x4001f738 + wait-циклы). По контексту (WDT/PMIC-стиль региона
0x4001Fxxx и регистров 0x10001xxx в соседях) [inferred, medium]: PMIC/RTC cold-reset
хелпер. До конца не трассирован.

### 4.5 DISCONNECT: cb = 0x40031394 [proven]

`лог "USB desconnected." (0x4004f6a9) → b 0x4002834c`: `0x40071120`-байт: `and #0xbf` /
`orr #0x40` — USB-физический detach (заняли сессию). Без reboot. Err-код DA — OK (ret 0).

### 4.6 DPC-исполнение и флаг 0x40069e8c [proven]

```
cmd_loop 0x4000875c:
0x400087c4  str 1,[0x40069e8c]                  ; loop-флаг = 1 (работаем)
0x40008bf0  bl 0x40001f08 -> dpc (0x40069dec)
0x40008bf4  if dpc->cb != 0:
0x40008c18    r4 = dpc->cb; r0 = dpc->arg
0x40008c28    blx r4                            ; <<< исполнение reboot-действия здесь
0x40008c2c    if dpc->name: cmp "reboot"(7) ==0 -> streq r8,[0x40069e8c], r8 = 0 (единственная
              запись r8 в функции: 0x4000892c mov r8,#0)  → флаг = 0 → цикл ЗАВЕРШАЕТСЯ
              (0x40008ca0: ldr [0x40069e8c]; cmp #1; beq continue)
0x40008c64  bl 0x40001f14                       ; dpc struct обнуление (+0,+4,+8)
0x40008c68+ err-обработка: любой код != OK/0 → str 3,[0x40069e8c] (0x40008c90) — аварийный
            выход из цикла
```

Итог по 0x40069e8c: это **не** «reboot-флаг», а **continue-флаг командного цикла**:
1 = продолжить, 0 = завершить сессию, 3 = аварийно завершить. DPC-"reboot" по завершении
колбэка ставит 0 → DA закрывает USB-сессию (согласуется с наблюдением «USB отваливается»
после REBOOT). [proven]

### 4.7 Передача boot mode «вниз» из REBOOT — нет [proven-by-absence]

Всеми REBOOT-путями touches: 0x10007024 (bic 0xff0 / orr 0xE / bfi bits29-31),
0x10007000/04/08 (WDT), 0x40071120 (USB). Ни один не пишет proinfo/RPMB/misc/ATAG-слоты
preloader'а. То есть **CMD:REBOOT сам boot-mode не передаёт** — вся надежда на то, что
SET-BOOT-MODE успел положить ниббль в 0x10007024.

## 5. Почему FASTBOOT + REBOOT грузит NORMAL — разбор цепочки

### 5.1 Что proven по всей цепочке

1. DA2 пишет ниббль 3 в 0x10007024 [proven §1.1].
2. REBOOT IMMEDIATE: bic 0xff0 — биты[3:0] сохраняет; bits29-31=4; WDT SW reset [proven §4.3].
3. Preloader (preloader_k6789v1_64/preloader.img) **не пишет** в 0x10007024 — только ldr в
   RGU-драйвере 0x23DF10-0x23E448 [proven-by-absence, re-preloader-bootmode-atag §3.1].
   В ATAG/boot-tag (builder 0x231694, поле +0x28 из 0x2F4264) попадает только режим из
   AT-диспетчера preloader'а — в BROM→DA2→reboot-сценарии он 0 [proven §1-2 той записки].
4. LK читает ниббль 0x10007024 через 0x500405B0 (& 0xF, с кэшем) и при ==3 ставит mode 0x63
   FASTBOOT [proven, re-lk-bootmode-priority §1.1/§1.2, приоритет #6 — ниже ATAG и ниже
   misc, но выше reboot-reason].
5. LK-геттер **сбрасывает ниббль в 0 после первого чтения** [proven, §1.1 той записки] —
   после каждой обычной загрузки регистр обнулён; каждый DA2-этап обязан ставить его заново
   (SET-BOOT-MODE это и делает).

### 5.2 Где рвётся [inferred, точка не локализована]

Статически звенья 1→4 совместимы, но наблюдение — NORMAL (22d9:2046 = preloader-stage
USB/handshake, затем обычный бут). Кандидаты на потерю ниббля:

- **(a) BROM** — между WDT-резетом и preloader'ом ROM-код читает RGU-регистры; в mask-ROM
  не заглянуть. Может потребить/занулить ниббль (например, интерпретировать bits как
  «download mode» и уйти в свою логику). [unverifiable statically]
- **(b) HW-семантика SW-reset**: bits[31:29]=4 — «SW reset» тип RGU; некоторые MTK RGU
  реализации аппаратно очищают trap-поле при программном (не watchdog-таймаутном) резете.
  [inferred, medium]
- **(c) PMIC full-reset**: если 0x22000000 в MODE — «PMIC full rst»-тип (строки
  "RGU PMIC full rst: true" 0x4004d599 в соседях), RGU-домен мог бы обнулиться. [inferred, low-medium]
- **(d) Прелоадер потребляет ниббль для своих решений** (rgu_status → ветки
  «WDT reboot bypass power key» и пр.), но записи нет — исключено [proven].
- **(e) Наблюдательная ошибка**: 22d9:2046 виден в окне preloader-handshake до того, как
  LK вообще выбрал режим; если хост не отсоединяется, preloader сидит в handshake и до LK
  дело доходит только по таймауту. Тогда ниббль мог дожить, а fastboot-окно просто не
  увидели. [inferred, low]

### 5.3 Дешёвые проверки (в порядке цены)

1. **READ-REGISTER 0x10007024 сразу после SET-BOOT-MODE FASTBOOT** — убедиться, что
   ниббль реально 3 (и что read-хендлер не кэширует).
2. **REBOOT WARM-RESET vs DELAY**: DELAY (cb 0x4003143c) делает тот же bic 0xff0 + WDT c
   timeout=3 — если DELAY даёт fastboot, а IMMEDIATE нет, виноват тип reset'а (гипотеза b/c).
3. **UART**: `oem p2u on`-недоступен (мы не в fastboot), но preloader/LK лог на UART
   напечатает `boot_mode_check:g_boot_mode is set %u` — прямая верификация, какой источник
   сработал (re-lk-bootmode-priority §5.6).
4. **Повторный DA-коннект сразу после reboot** (BROM Window): READ-REGISTER 0x10007024 —
   увидеть значение, дошедшее до нового прогона (BROM не должен его менять, если только
   не (a)).

## 6. Гипотеза RGU-ниббля как рабочий путь DA2→LK fastboot

**Механика есть** [proven]: mtkclient-хендлеры `CMD:WRITE-REGISTER` (0x4000700c) /
`CMD:READ-REGISTER` (0x40006eec) зарегистрированы (re-sec-dispatch §2.3), т.е. из DA2-сессии
можно сделать read-modify-write 0x10007024 (в т.ч. через custom_write в mtkclient), а
SET-BOOT-MODE FASTBOOT уже делает ровно нужную запись. WDT-путь reset'а ниббль не стирает.

**Разрыв** [inferred]: нормальная загрузка вместо fastboot — теряется между RGU и LK
(§5.2). Пока не пройден эксперимент §5.3.2/5.3.4, статус пути: **кандидат, не подтверждён**.
Важно: даже если ниббль доживёт — LK fastboot на locked-устройстве открыт (getvar/reboot/
`flashing unlock` работают, re-lk-rescue-surfaces §1), так что выигрыш реальный: это был бы
первый proven путь «DA2-сессия → следующая загрузка в fastboot» без кнопок.

Остальные каналы — закрыты [proven]:
- misc BCB «boot-fastboot» — LK не читает (только «boot-recovery») [re-lk-bootmode-priority §3];
- proinfo boot_mode_flag — вне приоритет-цепочки LK [§1.2];
- RPMB boot-info (set_boot_info, block+0xC lock-зеркало) — пишет только LK сам
  (0x50054744); в DA2 строк set_boot_info/RPMB-boot-info нет [proven-by-absence: rpmb-строки
  в DA2 — только key-program/counter из mmc/ufs-драйверов, вызовы не из SET-BOOT-MODE];
- ATAG/boottags [0x50112024] — пишет preloader, из DA2 недоступен (адрес SRAM-preloader
  области, DA2 туда не пишет) [proven §1.1 + re-preloader §2].

## 7. Строки/символы в DA2 по теме (survey, байты/xrefs проверены)

| VA | строка | xrefs |
|---|---|---|
| 0x40041583/0x400415f3 | CMD:REBOOT / CMD:SET-BOOT-MODE | таблица регистрации [proven] |
| 0x40042669/0x40042630/0x40042672 | FASTBOOT / META / ANDROID-TEST-MODE | только cmp в 0x40005d84 [proven] |
| 0x40043f04/0x40043f25/0x40043f45 | `mtk_boot_mode_flag.boot_mode/com_type/com_id=%d` | логи в 0x4000c8e0 (META→proinfo) [proven] |
| 0x40043f79 | `set_atm_mode` | регион ATM-ветки [inferred] |
| 0x400424a9/0x400424b0/0x400424df | `reboot` / OPLUS_DELAY_REBOOT / OPLUS_REBOOT_TO_EDL | 0x40005ba8 + cmd_loop memcmp [proven] |
| 0x40047f45-0x40047fb2 | `BOOT_REASON: %d`, `BOOT_MODE: %d`, `META_COM TYPE/ID/PORT`, `META LOG DISABLE`, `FAST META GPIO` | **xrefs НЕТ** (movw/movt sweep по всем cond — 0 попаданий) [proven-by-absence] — остатки preloader-общего кода, DA ATAG'и не строит |
| 0x400483ea/0x40048415/0x4004844a | `%s boot to LK by ATAG reason=%d addr=0x%x`, `UART META Connected…`, `emergency download mode` | **xrefs НЕТ** [proven-by-absence] (в preloader эти пути живые — 0x24F780 там; в DA2 линковка мёртвая) |
| 0x40042eb7/0x40042edb | GET-RPMB-KEY-STATUS / RPMB-KEY-STATUS | другой хендлер (RPMB key status), к boot-info отношения не имеет [inferred] |

## 8. Итоговый ответ на вопрос кампании

- **SET-BOOT-MODE работает на этом юните ровно так, как написан**: FASTBOOT = одна запись
  ниббля 3 в 0x10007024; META/ATM = proinfo-флаги. Команда НЕ «ломается» и не
  отбрасывается — эффект просто не доживает до LK.
- **REBOOT не переносит boot mode**: он либо WDT-ресетит (IMMEDIATE/WARM — мгновенно,
  DELAY — с таймаутом), либо ставит EDL-маркер (orr 0xE), либо отключает USB.
- **Единственный статически непротиворечивый путь DA2→LK-fastboot — RGU-ниббль**
  (0x10007024[3:0]=3 + WDT reset), и он же уже реализован в mtkclient
  (`shutdown(ShutDownModes.FASTBOOT)`). Наблюдаемый NORMAL означает потерю ниббля
  между RGU и LK — проверить экспериментами §5.3; если подтвердится, что дело в типе
  reset'а, — заменить IMMEDIATE на DELAY-путь (отправка action OPLUS_DELAY_REBOOT,
  mtkclient-хендлер его принимает).
- Без RGU-ниббля путей нет: misc-BCB, proinfo, RPMB, ATAG — все закрыты (§6).

## 9. Confidence

- **High/proven**: карты 0x40005d84/0x40005ba8 (все ветки, байты и литералы);
  FASTBOOT→`bfi`-запись ниббля 3 @0x4002a4c8; META/ATM→proinfo (read 0x400/write обратно
  через 0x40054374, поля +0x152/+0x153/+0x154); DPC-механика и семантика 0x40069e8c
  (continue-флаг, r8=0); состав CB'ов всех action'ов; отсутствие строк-ATAG-xrefs;
  downstream-приоритеты LK и preloader-absence — по компаньон-запискам.
- **Medium**: классификация 0x4002a710 (WDT TIMEOUT-поле) и 0x4001eae8-обёртки
  (COLD-RESET) — по формам вызовов; точное значение enum'ов mode (1/2/3) — из cmp-строк.
- **Unresolved**: точка потери ниббля между WDT reset и LK (BROM/hardware-семантика/
  PMIC-full-reset — §5.2); живое поведение DELAY vs IMMEDIATE — нужен эксперимент.
