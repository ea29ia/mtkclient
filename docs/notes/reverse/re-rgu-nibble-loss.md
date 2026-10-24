# RE: Кто стирает ниббль 0x10007024 в цепочке reset→LK (RMX3630, MT6789)

Date: 2026-10-24. Эксперимент (DA2-сессия): CUSTOMREGW ниббль 3 (FASTBOOT) в
`0x10007024` (readback `0x24002003`), затем ручной WDT SW-reset (`0x1209` →
`0x10007014`). Следующая сессия: `0x10007024 = 0x24002000` — ниббль [3:0] = 0,
остальные биты НЕ изменились.

Материал: `/home/musin/brom_0x1208.bin` (256 KB, BROM, VA = file offset),
`/home/musin/firmware/extracted/IMAGES/preloader_k6789v1_64.bin`
(32-битная Thumb-часть, **VA = file offset + 0x200F10**),
`/home/musin/firmware/extracted/IMAGES/da2_oplus.bin` (**ARM-mode**, VA = file
offset + 0x40000000), LK `docs/notes/rmx3630-lk/lk.img` (aarch64; VA = payload
offset + 0x50000000, payload @ file 0x200; все VA LK ниже = img_off − 0x200 +
0x50000000). Инструмент: capstone в `/home/musin/mtkclient/.venv`.

Статусы: **[proven]** = инструкции/байты прочитаны; **[inferred]** = вывод, помечен
уровнем уверенности.

---

## TL;DR — ответ на вопрос кампании

1. **Ниббль НЕ стирается ни BROM'ом, ни preloader'ом, ни reset'ом.** Полный
   статический sweep обоих бинарей: ни одной константы/пула/movw-movt-пары,
   адресующей `0x10007020`/`0x10007024` в BROM; в preloader единственный
   nibble-clearer (`bic #0xF` → `str`, VA 0x23DFA8) вызывается ровно один раз и
   **только при ниббле == 0xE**.
2. **Ниббль стирает сам LK — его boot-mode getter 0x500405B0**: при первом чтении
   кэширует `reg & 0xF` и **записывает обратно `reg & ~0xF`** [proven, код
   приведён в §4; в `re-lk-bootmode-priority.md` это уже было proven — теперь
   подтверждено экспериментально].
3. **Аппаратной потери нет**: в readback `0x24002000` сохранены ВСЕ биты, кроме
   ниббля, включая бит `0x2000`, который ставит preloader-овский WDT-драйвер
   (`0x10007024 |= 0x2000`, VA 0x23E402) — т.е. WDT SW-reset был **warm**,
   RGU non-rst пережил его, preloader прошёл и ниббль не тронул, LK прочитал
   ниббль и обнулил [proven-цепочка, §5].
4. **Следствие: механизм РАБОТАЕТ.** Ниббль 3 дошёл до LK и был потреблён:
   `boot_mode_check` при ниббле 3 (и пустых источниках выше приоритетом — ATAG=0,
   misc-BCB пуст, nibble не 0xC/2) ставит mode `0x63` FASTBOOT [proven по
   re-lk-bootmode-priority §1.2]. Наблюдаемое «нуббл стёрт» — это
   пост-LK-состояние, а не потеря. Если в предыдущем прогоне наблюдался NORMAL —
   проверять нужно окно/UART, а не RGU (§6).

---

## 1. BROM (brom_0x1208.bin) — не трогает 0x10007020/0x10007024 [proven-by-absence]

- Формат: старт ARM (вектора `080000EA…` @0x0), основной код — **Thumb-2**
  (регион WDT-драйвера 0xBFA8–0xC00C дизассемблится только как Thumb; ARM-пары
  movw/movt на 0x100070xx отсутствуют).
- Sweep по всем трём способам адресации:
  1. literal pool `0x10007024`/`0x10007020` — **0 попаданий** (все `0x100070xx`
     слова: только 4 × `0x10007000` @ 0xC00C, 0xE70C, 0x15A08, 0x15A18; из них
     код-пул только 0xC00C, остальные — данные);
  2. ARM `ldr rX,[pc,#imm]` forward/backward на эти пулы — 0 попаданий;
  3. Thumb-пары `movw #0x70xx` + `movt #0x1000` — 0 попаданий (все `movw 0x70xx`
     по файлу — ложные срабатывания на данных).
- Единственный код BROM, трогающий RGU, — WDT-драйвер вокруг пула 0xC00c:

```
; VA 0xBFA8 — BROM WDT SW-reset (единственный BL-caller 0xE572 — путь
; "security/download fail"; второй caller 0xE862 → 0xBFFC — error-путь)
0x0000bfa8  ldr r1,[pc,#0x60]        ; r1 = [0xC00C] = 0x10007000
0x0000bfaa  cmp r0,#0
0x0000bfac  beq 0xbfB4
0x0000bfae  orr r0,r0,#0x66000000
0x0000bfb2  str r0,[r1,#0x10]        ; 0x10007010 |= (arg | 0x66000000)
0x0000bfb4  ldr r0,[r1]
0x0000bfb6  bic r0,r0,#8
0x0000bfba  orr r0,r0,#0x22000000    ; WDT_MODE: key 0x22000000, бит3 снят
0x0000bfbe  str r0,[r1]
0x0000bfc0  movw r0,#0x1209
0x0000bfc4  str r0,[r1,#0x14]        ; WDT_SWRST = 0x1209
0x0000bfc6  bx lr
```

  Смещения, используемые от базы 0x10007000: **0x00, 0x04, 0x08, 0x10, 0x14,
  0xA4** (0xBFFC: `str [0x100070A4] |= 0x66000100` — тоже error-путь). Смещений
  0x20/0x24 **нет нигде**.

**Вывод: BROM не читает и не пишет 0x10007020/24 ни в каком пути — не очищает
нуббл и не «потребляет» его для boot-arbitrage** [proven-by-absence; ограничение:
если бы доступ шёл через нестандартный алиас базы — не найден; пул 0xA0000000
@0x15BA0 — к RGU-драйверу не относится].

## 2. Preloader — единственный clearer условный (nibble==0xE) [proven]

Все потребители 0x10007024 (ldr-literal на пулы file 0x3D020–0x3D49C), VA:

| VA | функция | callers (BL) |
|---|---|---|
| 0x23DF18 | read; `and #0x1C000000` → bool | 0x235A02 |
| 0x23DF30 | read; `and #0xF; sub #0xD` → bool (nibble==0xD) | 0x2285FC |
| 0x23DF48 | read; nibble==7 | 0x22863C |
| 0x23DF60 | read; nibble==0xE | 0x228618 |
| 0x23DF78 | read; nibble==0xA | 0x22862A |
| 0x23DF90 | read; nibble==0xB | 0x22865A |
| **0x23DFA8** | **read; `bic r1,#0xF`; `str` — ОЧИСТКА НИББЛЯ** | **0x228624** |
| 0x23DFB8 | setter: `bic #0xFF0; orr r0<<4; str` | **нет callers (dead)** |
| 0x23E354 | WDT-api (env-strings, bit23 0x800000 orr/bic в 0x10007024 — ниббль сохраняет) | 0x228596 |
| 0x23E3B8 | WDT reset-config: … `0x10007024 |= 0x2000` (0x23E402) — ниббль сохраняет | 0x23E372, 0x23E648, 0x23E694, 0x23E854, 0x23E864 |

Код clearer и его единственный caller (контекст VA 0x2285F0–0x228666 — маппинг
нуббля в boot-режимы preloader'а):

```
0x0023DFA8  ldr r0,[pc,#8]      ; r0 = [0x3D0A8] = 0x10007024
0x0023DFAC  ldr r1,[r0]
0x0023DFB0  bic r1,r1,#0xF      ; <<<< очистка ниббля
0x0023DFB4  str r1,[r0]
0x0023DFB6  bx lr

0x00228618  bl 0x23DF60         ; nibble == 0xE ?
0x0022861C  cbz r0,0x22862A
0x0022861E  movs r0,#0x64
0x00228620  str r0,[fp]         ; режим 0x64
0x00228624  bl 0x23DFA8         ; <<< clear — ТОЛЬКО в ветке 0xE
0x00228628  b 0x228666
```

Ниббль 3 (FASTBOOT) preloader'ом **не матчится ни в одну ветку** (0xD/7/0xE/A/B)
→ до clear не доходит, проваливается в нормальный boot-path. Записи «нуля в
регистр»/`bic` ниббля вне ветки 0xE нет [proven-by-absence по всем ldr-literal
xrefs пулов 0x10007024 — их ровно 10, все перечислены].

Примечание: вывод старого sweep'а («preloader не пишет 0x10007024 — только ldr»,
re-preloader-bootmode-atag §3.1) **неполон**: clearer существует, но мёртв для
ниббля ≠ 0xE. Для нашего случая (нуббль 3) вывод остаётся верным.

## 3. Аппаратура: SW-reset warm, non-rst переживает [proven, из readback]

`0x24002003 → reset → 0x24002000`: изменился **только** ниббль. Если бы reset
был full/cold (PMIC), весь регистр обнулился бы. Плюс бит `0x2000` в readback —
это `0x10007024 |= 0x2000` из preloader-WDT-драйвера (0x23E402), т.е. после
reset'а прошёл preloader. Ручной SWRST `0x1209` без записи WDT_MODE в этой
сессии сработал как warm reset и ниббль «потерял» не hardware [proven по
эффекту; семантика бит 0x24000000/0x2000 — HW-latched RGU_REQ_MODE-поля,
inferred, medium].

## 4. LK — вот кто стирает [proven]

Getter (lk.img payload VA 0x500405B0 по маппингу записки; img-байты @0x40738):

```
0x50040538  adrp x8, 0x50C3000
0x5004053C  ldrb w0,[x8,#0xB48]     ; кэш-байт
0x50040540  cmp w0,#0xF             ; sentinel «ещё не читали»
0x50040544  b.ne ret
0x50040548  mov x9,#0x7024; movk #0x1000,lsl16; movk #0xFFFF,lsl48
0x50040554  ldr w10,[x9]            ; 0xFFFF000010007024
0x50040558  and w11,w10,#0xF        ; вернуть ниббль
0x5004055C  and w10,w10,#0xFFFFFFF0 ; <<<< ниббль -> 0
0x50040560  strb w11,[x8,#0xB48]    ; кэш
0x50040564  str w10,[x9]            ; ЗАПИСЬ ОБРАТНО — ниббль стёрт
0x50040568  ldrb w0,[x8,#0xB48]; ret
```

Рядом тот же RGU-кластер LK: nibble-setter (VA 0x50040514, `and w9,#~0xF; orr
w0&0xF; str`), setter bits[11:4] (0x50040570), reader bits[11:4] (0x50040590),
setter bits[31:29]=`bfi w9,w0,#0x1d,#3` (0x500405A8), WDT-config
(`MODE = (old & ~0x2200004F) | 0x22004D00/0x22000000` + restart 0x1971,
0x500405C4) и **LK-овский SW-reset** (VA 0x500406CC: `MODE = (old &
0xDDFF_FFB0) | 0x22000000`, затем `0x10007014 = 0x1209`) — та же каноническая
warm-последовательность, что в BROM.

Уточнение к записке re-lk-bootmode-priority §1.1: «getter 0x500405B0» — реально
на 0x500405B0 лежит setter bits[31:29]; getter (+очистка) — **0x50040538**.
Функционально всё описано верно.

## 5. Цепочка эксперимента — полная реконструкция [proven/inferred]

1. DA2-сессия: CUSTOMREGW ниббль 3 → readback `0x24002003` [пользователь, proven].
   `0x24002000` к этому моменту — уже HW/preloader-latched состояние RGU
   (bit13 `0x2000` — preloader-WDT `|= 0x2000`; 0x04000000/0x20000000 —
   HW-latch, inferred medium).
2. SWRST `0x1209` → **warm reset**, весь регистр сохраняется [§3, proven].
3. BROM стартует: ниббль не трогает [§1, proven-by-absence].
4. Preloader: WDT-иниц (`|= 0x2000`, ниббль жив), nibble-чеки 0xD/7/E/A/B — 3 не
   матчится, nibble-clear не выполняется; в ATAG передаётся 0 [§2 + старая
   записка, proven].
5. LK: `boot_mode_check` (0x5000AB24) первым делом вызывает getter → getter
   **читает ниббль 3, кэширует, пишет регистр с нулевым нибблем** [§4, proven] →
   в `boot_mode_check` `hw==3` → `mode = 0x63` FASTBOOT [proven по
   re-lk-bootmode-priority].
6. Следующая BROM-сессия видит `0x24002000` — ожидаемый пост-LK-стейт.

**Точка потери = шаг 5, и это не потеря, а потребление.**

## 6. Что это значит и как верифицировать

- Прошлый вывод «наблюдается NORMAL» не противоречит цепочке только если
  (а) сессию смотрели мимо fastboot-окна, или (б) сработал источник с приоритетом
  выше ниббля-3 (ATAG≠0 — исключено; misc-BCB «boot-recovery» дал бы RECOVERY,
  не NORMAL; rc_wdt+lock дал бы META/FASTBOOT). Приоритетная таблица не даёт
  NORMAL при живом ниббле 3 → [inferred, high]: **прогон, скорее всего, реально
  уходил в fastboot**, либо boot_mode_check не добегал до выбора (ранний
  preloader-handshake, гипотеза (e) из re-da2 §5.2).
- Верификация: (1) UART-лог `boot_mode_check:g_boot_mode is set %u` — если 0x63,
  цепочка proven end-to-end; (2) повторить DA2→REBOOT и сразу подключиться
  mtkclient'ом в BROM-окно ДО LK — readback покажет 3 (BROM не чистит);
  (3) против misc-BCB-гипотезы — hexdump misc[0..0xE].
- **Bypass не нужен**: «очиститель» — контрактный consume LK. Сброс с
  сохранённым нибблем достижим обеими последовательностями:
  - DA2-native: CMD:REBOOT IMMEDIATE (0x40031420: `bic 0xFF0` ниббль сохраняет,
    `WDT_MODE=0x230001FF → |= 0x22000000(+0x20-ветка) → |= 1`, restart 0x1971,
    bits[31:29]=4) [proven §re-da2 4.3 + перепроверено в ARM-дизасме];
  - ручная каноническая warm-SWRST через CUSTOMREGW (как в BROM 0xBFA8 / LK
    0x500406CC): **(1)** `0x10007000: (old & ~8) | 0x22000000` (ключ обязателен —
    без него SWRST-запись игнорируется/MMIO-защита), **(2)** `0x10007014 = 0x1209`.
    В эксперименте она уже сработала warm и ниббль донесла.
- EXP-CALL-FUNC на 0x40031420 не требуется; он тоже не трогает ниббль.

## 7. Confidence

- **Proven**: BROM — отсутствие любых адресаций 0x10007020/24 (3 метода sweep),
  карта BROM-WDT-драйвера (0xBFA8/0xBFC8/0xBFF2/0xBFFC + callers 0xE572/0xE862);
  preloader — 10 xrefs пулов 0x10007024, clearer 0x23DFA8 (`bic #0xF`+str) с
  единственным caller 0x228624 в ветке nibble==0xE; preloader `|= 0x2000`
  (0x23E402); DA2 0x40031420/0x2A4E4/0x2A53C/0x2A5C0/0x2A728 в ARM-режиме
  (байты); LK getter с очисткой ниббля (img 0x40738) и LK-SWRST (img 0x406CC).
- **Inferred**: битовые семантики 0x24000000/0x2000 (HW-latch/preloader-запись),
  то, что «next session» = пост-LK-состояние (единственная непротиворечивая
  модель наблюдения), вывод о фактическом входе в fastboot в прошлом прогоне.
