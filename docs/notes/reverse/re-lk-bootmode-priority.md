# RE: LK boot-mode selection на RMX3630 (MT6789) — приоритеты источников, fastboot-вход, misc BCB, BCAB

> **ERRATA (2026-10-24, audit #2)** — this document is **systematically wrong**:
> every *code* VA is **+0x78** too high (entry 0x5000AB24 → real **0x5000AAAC**,
> caller 0x5000E1D4 → **0x5000E15C**, BCB read 0x50069C88 → **0x50069C10**,
> misc open 0x50069BFC → **0x50069B84**, malloc 0x5006AD00 → **0x5006AC88**,
> strcmp 0x5006CD64 → **0x5006CCEC**, HW getter 0x500405B0 → **0x50040538**,
> oplusreserve 0x50005458 → **0x500053E0**, kpoc 0x5001F078 → **0x5001F000**).
> Semantic errors: ATAG 1 → mode **1 (META)**, ATAG 7 → mode **7 (banner
> "UNKNOWN BOOT")** — neither is fastboot; only **0x63** is FASTBOOT
> (HW nibble 3 at 0x5000ACA4, or rc_wdt-class && lock==3 at 0x5000ACBC→0x5000AD04).
> rc_wdt + locked → **RECOVERY** (mode 2), not META. HW nibble 0xB → **stores 0xB**.
> BCB compare is `strcmp` (NUL required at misc[13]). BCAB is read **0x20 B at
> offset 0x800** (not 0x800 B at 0) and **0x80C = BCAB+0xC is a live field** that
> LK itself rewrites with 0x77 — "safe to edit" is wrong.
> See `re-consistency-audit-2.md` §C6/§C7. **Regenerate, do not patch.**

Date: 2026-10-24. Target: `docs/notes/rmx3630-lk/lk.img`, payload `lk` (file off 0x200,
size 0xE4600). VA = payload_offset + 0x50000000 (маппинг тот же, что в
`re-lk-seccfg.md` / `re-lk-rescue-surfaces.md`; все адреса — реальные VA).
Method: objdump-дизассемблер (aarch64, `--adjust-vma=0x50000000`) + адресная арифметика
ADRP/ADD + dump строк по VA. Companion: `re-lk-rescue-surfaces.md` (§3 там — summary;
здесь полный код-путь и ответы на вопросы 2–4).

Статусы: **[proven]** = прямо из дизассемблированного кода/байтов; **[inferred]** =
вывод по косвенным данным (помечен уровень уверенности).

---

## TL;DR

1. Точка входа выбора режима — **0x5000AB24** (не 0x5000AAAC: это пролог-хвост
   соседней функции-логгера). Порядок приоритета (первый сработавший → итог):
   **(1) preloader ATAG/boottags** [0x50112024] через early getter 0x50003738;
   **(2) HW-регистр 0xFFFF000010007024, младший ниббл** (getter 0x500405B0,
   кэш-байт [0x500C3B48]); **(3) misc BCB "boot-recovery"** (read 0xE B @ misc+0);
   **(4) reboot-reason таблица {0,4,6,8,9,0xA,0x1E,0x1F,0x20,0x21} @0x500BF6A8**
   + GPIO-ветки (recovery/fastboot/vol_down) — самый низкий приоритет.
2. **FASTBOOT (0x63) из LK-стороны даёт только ниббл 3 в 0x10007024**
   (0x5000AD1C: `cmp w8,#3; mov w8,#0x63`). Значение 7 в ATAG тоже даёт
   g_boot_mode=7 (== 0x63 enum FASTBOOT, banner "=> FASTBOOT MODE"), т.е.
   preloader ATAG 1/7 → mode 7 [proven]. 0x63 в ATAG не проверяется — только 1/4/7.
3. **misc BCB**: open "misc" 0x50069BFC, read 0xE B @ offset 0 (0x50069C88),
   memcmp с "boot-recovery" (0x5008F7C0) @0x5000ACD8. **"boot-fastboot" LK на
   старте НЕ читает** — строка 0x5008F7B0 используется только писателем BCB
   (0x50006928 ← reboot-fastboot handler). Опровергнуто: fastboot через BCB
   невозможен. Только recovery.
4. **BCAB reader 0x5001E040**: читает **0x800 байт по misc offset 0** (byte
   offset = 0x800 × 0x20 / 512 = 0; цифры 0x800/0x20 — это count/приоритет
   arg-регистры, не секторная арифметика). "На живом устройстве BCAB на 0x800"
   — опровергнуто: LK читает его с offset 0 (конфликт с BCB-командой — потому
   reboot-recovery затирает 0x1800 байт). Повреждённый BCAB: если magic@+4
   == 0, LK печатает "boot_ctrl magic number is zero for nonAB project" и
   молча игнорирует (нет recovery-fallback, нет boot-loop из-за BCAB).
   Поле 0x80C вне 0x28-байтной структуры контроля — вообще не читается.

---

## 1. boot_mode_check: полный код-путь и приоритеты

### 1.1 Точки входа и глобальные переменные

| что | VA | proven |
|---|---|---|
| функция выбора режима (реальная точка входа) | **0x5000AB24** | да |
| 0x5000AAAC | хвост функции-логгера (`boot_mode_check:g_boot_mode is set %u` 0x50090FC8 печатается отсюда по g_boot_mode) | да |
| g_boot_mode (байт) | **[0x50113240]** (`adrp x21, 0x50113000` + `strb w8,[x21,#0x240]` @0x5000AED4) | да |
| caller | 0x5000E1D4 (в banner-функции 0x5000E1BC, сразу после 0x50015C18) | да |
| early getter boottags | **0x50003738** → `ldr w0,[0x50112024]` | да |
| reboot-reason getter | 0x5000372C → `ldr w0,[0x50112020]` | да |
| HW boot-arg getter | **0x500405B0**: если кэш-байт [0x500C3B48]==0xF (первый вызов), читает `*(u32*)0xFFFF000010007024`, кэширует `reg & 0xF` и сбрасывает ниббл регистра в 0; иначе отдаёт кэш | да |
| reboot-reason таблица | **0x500BF6A8** = {0,4,6,8,9,0xA,0x1E,0x1F,0x20,0x21} (байты прочитаны из образа, proven) | да |
| seccfg lock_state getter | 0x50032724 → 0x50082B58 (`mm_backup_partition`-путь; ошибка → w0=0x103000=**invalid**, не 3) | да |

Псевдокод 0x5000AB24 (проверено инструкция-в-инструкцию):

```
g_boot_mode = [0x50113240] (предустановка, обычно 0)

v = early_getter_0x50003738()          // [0x50112024], preloader PL boottags
if (v == 1 || v == 7)      -> mode 7   @0x5000AB5C; exit
if (v == 4)                -> mode 4   + append "oplus_ftm_mode=factory1" (0x50090F9A)
                                          через 0x5001827C (cmdline append); exit
// иначе — дальше

hw = hw_getter_0x500405B0() & 0xFF
if (hw == 0xC):                        // agingtest @0x5000AB8C
    print "start agingtest check" (0x5009104D)
    append "oplus_ftm_mode=ftmaging" (0x50091064)
    print "agingtest check pass"/"no need agingtest" (0x50090FB2/0x5009107C)
    if platform=="MT6896" (0x5009109F) && strcmp(sbuf,"...")==0:
        print "agingtest in ftm" (0x500910A6)
        append "androidboot.selinux=permissive" (0x500910B8)
        mode 4; exit
    else:
        print "no need agingtest"; // fall-through (0x5000AC08)

if (hw == 2) -> mode 2 (RECOVERY) @0x5000AC20; exit   // ВАЖНО: ДО misc-BCB

// --- misc BCB (0x5000AC24) ---
bdev = misc_open("misc")               // 0x50069BFC, имя 0x5008FB83 "misc"
if (bdev == NULL):
    print "...failed to open misc..." (0x50090EEE, line 242)
    goto check_gpio_recovery (0x5000ACAC)
buf = malloc(0xE)                      // 0x5006AD00
if (!buf): print err (0x50091131, line 247); goto close_and_gpio
n = misc_read(bdev, buf, 0, 0xE)       // 0x50069C88; x0=bdev,x1=buf,x2=0(off),x3=0xE
if (n <= 0xD):                         // "read less than 13 bytes"
    print err (0x50091131, line 252)
else:
    if (memcmp(buf, "boot-recovery", 13) == 0):   // 0x5006CD64, "boot-recovery" 0x5008F7C0
        free(buf); misc_close; -> mode 2 (RECOVERY) @0x5000AED0; exit
    // else: print buf (0x500A0E85 "%s"), free, close, fall-through
free(buf); misc_close(0x50069B8C)

// --- rc_wdt / lock_state gate (0x5000ACF8) ---
if (check_0x5000B260() == true):       // rc_wdt (watchdog-reboot family, строка
                                       // "rc_wdt_status = %d, rc_exp_type = %d" 0x50090FD7)
    if (lock_state() != 3): -> mode 1 (META-branch 0x5000AD00) ... exit
                                       // (mode 1 + print 0x50091156 "recovery_check gpio...")
// --- hw nibble: FASTBOOT (0x5000AD1C) ---
hw = hw_getter() & 0xFF
if (hw == 3): mode = 0x63 (FASTBOOT) @0x5000AD2C; exit
if (check_0x5000B260() && lock_state()==3):
    w = 0x50021DA4(0xC)                // GPIO read (pin 12)
    print "fastboot_check gpio condition is %d" (0x500911FD, line 294)
    goto 0x5000AD2C                    // -> mode 0x63 всё равно (даже если GPIO!=0!)
                                       // ВЕТКА БЕЗУСЛОВНО СТАВИТ 0x63 — см. §2
// --- reboot reason (0x5000AD80) ---
reason = [0x50112020]                  // 0x5000372C
if (0x5001F078() == 0)                 // kpoc/charging check -> skip table
    goto fallback (0x5000AE74)
if (reason in {0,4,6,8,9,0xA,0x1E,0x1F,0x20,0x21})   // таблица @0x500BF6A8,
    goto hw2_check (0x5000AE74)        // 10 компаров 0x5000AD98..0x5000AE0C
// reason не из таблицы:
print "...boot reason %d..." (0x50091238, line 340)
r = 0x5001EC38(); if r: r &= 0x5001EE14(); if r: r = !0x5001ECC0()
mode = r ? 8 (POWEROFF-CHARGING) : 0 (NORMAL)       @0x5000AE44/0x5000AEFC; exit

// --- 0x5000AE74: reason из таблицы ИЛИ kpoc-skip ---
hw = hw_getter() & 0xFF
if (hw == 0xA) -> mode 0xC (agingtest-recovery branch, 0x5000AE84); exit
if (hw == 0xB) -> mode = g_boot_mode (pass-through, 0x5000AEC4); exit
if (0x50005458() != 0)                 // oplusreserve1 boot-header check
    -> mode 2 (RECOVERY) @0x5000AED0; exit
// иначе mode остаётся предустановленным g_boot_mode (обычно 0=NORMAL); exit
```

### 1.2 Таблица приоритетов (итог)

| # | источник | код | условие | результат |
|---|---|---|---|---|
| 1 | preloader ATAG/PL boottags [0x50112024] | 0x5000AB38..0x5000AB78 | v==1 \| \| v==7 → 7; v==4 → 4 | 7 = FASTBOOT; 4 = FACTORY (+factory1 cmdline) |
| 2 | HW reg 0x10007024 nibble==0xC | 0x5000AB7C..0x5000AC04 | agingtest-платформенный чек | 4 (agingtest, +permissive) |
| 3 | HW nibble==2 | 0x5000AC14..0x5000AC20 | до misc | 2 = RECOVERY |
| 4 | misc BCB "boot-recovery" | 0x5000AC24..0x5000ACE4 | первые 13 B == "boot-recovery" | 2 = RECOVERY |
| 5 | rc_wdt + lock_state | 0x5000ACF8..0x5000AD18 | 0x5000B260()==true && lock_state!=3 | 1 = META-ветка |
| 6 | HW nibble==3 | 0x5000AD1C..0x5000AD30 | — | **0x63 = FASTBOOT** |
| 6b | fastboot_check GPIO | 0x5000AD34..0x5000AD7C | 0x5000B260 && lock==3 → GPIO(12) | 0x63 = FASTBOOT (безусловно) |
| 7 | reboot reason ∈ таблица 0x500BF6A8 | 0x5000AD80..0x5000AE0C | && 0x5001F078()!=0 | не задаёт режим сам; уходит на шаг 8 |
| 8 | reason∉таблица: 0x5001EC38/0x5001EE14/0x5001ECC0 | 0x5000AE10..0x5000AEFC | комбинация флагов | 8 = POWEROFF-CHARGING или 0 = NORMAL |
| 9 | HW nibble==0xA | 0x5000AE74..0x5000AE88 | после reason-таблицы | 0xC (aging-recovery) |
| 10 | HW nibble==0xB | 0x5000AEB8..0x5000AEC4 | pass-through | без изменений |
| 11 | oplusreserve1 boot-header (0x50005458) | 0x5000AEC8 | возврат !=0 | 2 = RECOVERY |
| 12 | ничего не сработало | 0x5000AED8 | — | предустановленный g_boot_mode (0=NORMAL) |

Что перебивает что: **ATAG > (agingtest-0xC) > HW-2 > misc BCB > lock/wdt >
HW-3/GPIO > reboot-reason/charging > oplusreserve1 > default**. Т.е. если
preloader положил 1/7/4 в boottags — до misc дело не дойдёт никогда.

Misc-BCB читается **только если ATAG не 1/4/7 и HW-ниббл не 2 и не 0xC**.
"boot-recovery" перебивается всем, что выше; HW nibble 3 (fastboot) проверяется
**после** misc — значит BCB "boot-recovery" перебивает даже HW fastboot-ниббл 3.

---

## 2. Как LK грузится в FASTBOOT (0x63)

Проверка всех гипотез:

- **boot_mode == 7**: да, enum 7 == FASTBOOT — jump-таблица баннеров
  0x5000E208 (`ldrb w11,[x9,x8]` по таблице 0x50093A89; для индексов 0..8) и
  явный `cmp w8,#0x63` @0x5000E238 → banner 0x50092A87 "=> FASTBOOT MODE".
  Значение **7** попадает в [0x50113240] из **двух** мест: (а) ATAG==1 или 7
  @0x5000AB5C (`mov w0,#7`), (б) HW ниббл==3 @0x5000AD2C (`mov w8,#0x63`).
- **boot_mode == 3**: нет. 3 == UNKNOWN ("=> UNKNOWN BOOT" 0x50092A9A).
  Ниббл 3 в регистре → mode 0x63, а не 3 [proven].
- **0x63 в ATAG**: не обрабатывается. Early getter проверяет только 1/4/7
  (@0x5000AB40..0x5000AB58: cmp 1, cmp 4, cmp 7). 0x63 прошёл бы как
  «не совпало» и ушёл бы вниз по приоритету.
- **Ниббл 3 в регистре**: да — единственный HW-путь в fastboot (0x5000AD24).
- Значения 1/7 → mode 7, 4 → factory из ATAG — **подтверждено кодом**
  (0x5000AB40-B78; 4 дополнительно добавляет `oplus_ftm_mode=factory1`).

**[proven, важная деталь]** Ветка fastboot_check GPIO (0x5000AD34-0x5000AD7C):
если rc_wdt-чек 0x5000B260()==true и lock_state==3, LK читает GPIO 12
(0x50021DA4), печатает "fastboot_check gpio condition is %d" — и **в любом
случае** прыгает на `mov w8,#0x63` (0x5000AD2C→0x5000AD7C `b 0x5000AD2C`).
Условие GPIO ни на что не влияет (результат печатается, но не проверяется).
Это «форс-фастбут» при watchdog/rc-состоянии + залоченном SECCFG.

Итого, значения/источники, дающие FASTBOOT MODE:
1. ATAG/boottags [0x50112024] = 1 или 7 (пишет preloader, из flash недоступно);
2. HW reg 0x10007024 ниббл == 3 (пишет preloader; LK сам пишет туда же через
   0x5004058C — `set_reboot_reason(3)` из reboot-bootloader handler 0x500068E8);
3. rc_wdt-состояние (0x5000B260) при lock_state==3 (unlock+watchdog-reboot).

С flash-стороны (DA2) **ни один из этих трёх недостижим напрямую** — все три
канала инициализируются preloader'ом до LK. [inferred, high]

---

## 3. misc BCB reader: адреса и «boot-fastboot»

Чтение в boot_mode_check (все proven):

| шаг | VA | детали |
|---|---|---|
| open "misc" | 0x50069BFC (имя-строка "misc" @0x5008FB83) | поиск по списку bdev-имен 0x500DBEF8 через strcmp 0x5006CD64 |
| alloc 0xE | 0x5006AD00 (malloc) | |
| read | **0x50069C88**(bdev, buf, **offset=0**, **len=0xE**) | врапер: проверки len/off, вызов `bdev->read` по [bdev+0x68]; реальный block-IO driver внутри |
| memcmp | 0x5006CD64 @0x5000ACD8 | buf vs "boot-recovery" (0x5008F7C0), n=13 |
| close/free | 0x50069B8C / 0x5006AE30 | |

Reader (0x50069C88) — простой byte-range read: x2 = offset (0), x3 = length
(0xE). Никакой секторной арифметики: **BCB читается ровно с offset 0**.

**"boot-fastboot" на старте — ОПРОВЕРГНУТО [proven]**:
- строка "boot-fastboot" (0x5008F7B0) используется ровно в двух местах, оба —
  **писатель** BCB 0x50006928 (call sites 0x50006998 ← reboot-fastboot handler
  0x5000691C, и 0x5000D488);
- единственный memcmp boot-пути — "boot-recovery" (13 B) в boot_mode_check;
- остальные callers misc-read (0x5000D3A8 и др.) читают oplusreserve1/
  OP_LK_LOG_STORE (строки 0x5008EEFA) — не BCB;
- "load recovery image" и RECOVERY Mode — единственный BCB-исход.

Следствие: **записав "boot-fastboot" в misc, LK ничего не сделает** (не
проверяется) — устройство загрузится NORMAL. Только "boot-recovery" работает.

Писатель (для полноты, из rescue-surfaces §4, подтверждено): 0x50006928(str) —
open misc, memset 0x1800 байт, str→offset 0, write 0x1800 @ offset 0
("miscbio_write f..." 0x5008FB83-строка лога; "bio_write failed" 0x5008FB88).

---

## 4. boot_control BCAB reader 0x5001E040

### 4.1 Реальная сигнатура и offset

Реальный вход — **0x5001E044** (0x5001E040 = `ret`; ADRP-фиктивный вход).
Сигнатура: `int read_write_partition_info(u8 *out /*x0*/, u32 rw /*x1: 0=read,1=write*/)`.
Read-путь @0x5001E0D8:

```
bdev = misc_open("misc")                    // 0x50069BFC, "misc" 0x5008FB83
n  = misc_read(bdev, sp_buf, 0, 0x800)      // 0x50069C88: x2=0 (offset), x3=0x800 (len)
```

Т.е. **читается 0x800 байт с offset 0 в misc**. Цифры «0x800/0x20» из доков —
это (len=0x800) и (x3/w3=0x20 — **приоритет IO**, аргумент враппера write-пути
0x50069AC8 @0x5001E14C: `mov w2,#0x800; mov w3,#0x20`), **не** сектор-сдвиг.
Byte offset = 0. [proven; «BCAB на 0x800» — опровергнуто]

Проверки read-пути:
- `cmp w0, #0` (n<=0 → err 0x5009819F "...read fail...", ret -5);
- `ldr w8,[sp+4]` — magic @ buf+4; `0x42414342` ("BCAB", `movk w9,#0x4241,lsl16; mov w9,#0x4342`);
  - magic == BCAB → success: копирует 0x20 байт буфера в *out (0x5001E1F4);
  - magic == 0 → print **"boot_ctrl magic number is zero for nonAB project"**
    (0x500981C6, line 170) и **ret 0 (success, данные не копируются)** — тихий ignore;
  - magic != 0 и != BCAB → восстановление @0x5001E1A4: LK **сам чинит блок**:
    сохраняет w10=halfword@[sp+9] (`& 0xFFF8 | 2`), пишет magic BCAB, +8=1, +0xC=0x77 ('w'),
    +0xE=0x77, и вызывает checksum-calc 0x5005B7BC + **write-back 0x1C байт**
    (второй вызов 0x5001E044(1=write)) — затем копирует в *out.

### 4.2 Повреждённый BCAB (наш случай: поле 0x80C изменено)

- Смещение 0x80C **находится за пределами первых 0x28 байт структуры**,
  которые LK вообще потребляет (контрольные поля: magic@+4, +8..+0xF flags,
  +0x10..0x27 — payload, копируемый в out). Читается целиком 0x800, но
  семантически используются: magic(+4), halfword(+9) при ремонте,
  +0xC (+0xE) перезаписываются константами 0x77 при ремонте, payload 0x10..0x27.
- **0x80C (от начала misc) = байт внутри 0x800-байтного блока на offset 0x80C —
  за пределами структуры (структура ≤0x28), LK его не читает семантически.**
  Изменение этого поля не влияет ни на BCAB-логику, ни на BCB-команду
  (та смотрит только offset 0..0xD). [proven по диапазонам использования]
- Если бы был повреждён сам блок (magic): ветки — «magic==0 → ignore, ret 0»
  или «magic искажён → self-repair и rewrite». **Fallback на recovery/boot-loop
  из-за BCAB отсутствует**: ни одна ветка 0x5001E040 не возвращает mode и не
  пишет BCB. [proven]
- Кто вызывает: 0x5001E044 зовут 0x5001DF84, 0x5001E1F0 (само-починка),
  0x5001E274 (set_active_slot 0x5001E338-семейство), 0x5001E46C, 0x5001E510 —
  все в A/B-slot машине; в boot_mode_check BCAB **не участвует**.
- Boot-loop/recovery от повреждённого misc: возможен только через
  **"boot-recovery" в байтах 0..0xD** (читается boot_mode_check). Если при
  изменении поля 0x80C туда попала строка "boot-recovery" (например, при
  неудачном редактировании или чужом инструменте, писавшем BCB) — вот это
  даёт постоянный RECOVERY на каждом старте. Проверить: hexdump misc[0..0x10]:
  если там "boot-recovery" — стереть нулями → NORMAL вернётся. [inferred, high;
  сам механизм BCB→RECOVERY proven]

---

## 5. Рекомендации: как гарантированно получить fastboot на locked+SBC

1. **Каналы FASTBOOT все preloader-owned** [proven]: ATAG boottags (1/7),
   HW-reg nibble 3, rc_wdt+lock. Из позиции «DA2 flash write» ни один не
   выставляется. Единственный LK-внутренний способ записать nibble 3 —
   `set_reboot_reason(3)` (0x5004058C) из handler'а `reboot-bootloader`
   (0x500068E8), т.е. нужно уже находиться в fastboot. Замкнутый круг.
2. **Достижимый из flash способ попасть в fastboot — HW key-combo**
   (preloader-уровень, не LK):volume-key combo определяет preloader. Это вне
   LK-образа; в LK fastboot только подтверждается нибблом 3. [inferred, high]
3. **Misc BCB fastboot — невозможен** [proven]: LK не читает "boot-fastboot".
   Писать "boot-recovery" имеет смысл только если цель — recovery.
4. **Не трогать**: не класть "boot-recovery" в misc[0..0xD] случайно (даёт
   вечный recovery); поле 0x80C безопасно для LK, но убедиться, что misc[0..0xE]
   нулевые; BCAB-ремонт LK сам перепишет +0xC/+0xE = 0x77 при первом же старте,
   поэтому ручные правки BCAB внутри 0x28 могут откатиться.
5. **Реальный путь разблокировки на locked+SBC** — через сам fastboot, если он
   достигнут комбо: `flashing unlock` (0x500076A8, flagA=1/flagB=0 → работает
   locked) + arm frp[-4:] через DA2 (см. re-lk-rescue-surfaces.md §6-7).
6. Диагностика на UART: если устройство грузится, `oem p2u on` покажет строку
   `boot_mode_check:g_boot_mode is set %u` — она печатает итоговый режим и
   прямо верифицирует, какой источник сработал (значение 7/0x63=fastboot,
   2=recovery, 4=factory, 0=normal, 8=charging, 1=meta).

## 6. Confidence

- **High/proven**: точка входа 0x5000AB24 и полный порядок приоритетов;
  семантика ATAG 1/7→7, 4→4; ниббл 2→recovery, 3→0x63, 0xA→0xC, 0xB→pass-through;
  таблица reboot-reason {0,4,6,8,9,0xA,0x1E,0x1F,0x20,0x21} (байтовый дамп);
  misc BCB read offset 0 len 0xE memcmp 13 B "boot-recovery"; отсутствие
  boot-fastboot-ридера; BCAB read offset 0 len 0x800, magic@+4, ветки
  ignore/self-repair; безусловный 0x63 в fastboot-GPIO ветке.
- **Medium**: семантика rc_wdt-чекера 0x5000B260 (имя по строке лога);
  назначение конкретных reason-кодов таблицы (HW_reboot и т.д. — имена строк
  при 0x500BF7DC); точная роль 0x5001F078 (kpoc/charging — по позиции в коде);
 /pass-through HW nibble 0xB (что за режим-носитель).
- **Resolved из прошлого раунда**: offset BCAB внутри misc = 0 (было "TBD");
  caller 0x5001E040 = A/B slot-машина 0x5001DF84/0x5001E338/0x5001E46C/0x5001E510.
