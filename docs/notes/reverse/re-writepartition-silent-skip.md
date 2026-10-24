# RE: WRITE-PARTITION — где программа-фаза молча не пишет (трассировка до UFS)

Дата: 2026-10-24. Бинарь: `/home/musin/firmware/extracted/IMAGES/da2_oplus.bin`
(356296 B, ARM32, **VA = file offset + 0x40000000**). Инструмент: capstone
(CS_ARCH_ARM, CS_MODE_ARM) из `/home/musin/mtkclient/.venv`, все адреса/байты ниже
прочитаны из файла напрямую. Контекст: `re-write-chain.md`, `re-write-partition-offset.md`,
`re-writeflash-scrubber.md`, `re-postwrite-hang.md`, `re-consistency-audit.md`.

## TL;DR

1. **Два крупных исправления модели из `re-write-chain.md`:**
   - **`0x4002aac0` ("program dispatcher", `[0x40054320+0x10]`) — МЁРТВЫЙ КОД.** Ни одного
     `bl` на него, ни одной загрузки `[0x40054320+0x10]` в коде (полный скан bl/blx +
     скан `movw 0x4320`-последовательностей). Путь «engine-2 → program via 0x4002aac0»
     из write-chain §3 — **ошибка**.
   - **`0x40008234` ("commit") — `bx lr`, пустышка (подтверждено байтами `1e ff 2f e1`).**
     Запись во flash НЕ делается ни в data-цикле engine-2, ни в close/commit.
2. **Реальный писатель — DMA-callback «потребитель» `0x4002ff78`**, регистрируемый
   `0x400096d8(0x10000, 0x4002ff78, 0, 0x10)` в engine-2 (0x4003076c). Он на каждый
   принятый чанк вызывает `0x4002f804(base,len)` — там **hash-binding/img_auth gate**,
   а затем писатели-хэндлы `0x4002d5a8` (bulk) / `0x4002dd24` (sparse, magic `0xED26FF3A`)
   → `0x4002d66c`/`0x4002e4dc` → `blx [0x40054374+4]` = `0x4002e744` → `0x4002eb80`
   (dispatch по типу storage) → UFS `0x40030ec4` → `0x400200ec` (очередь UFS).
3. **Оп-таблица `0x40054330` — это НЕ flash-операции, а USB-транспорт** (переделка
   live-пробы: [+8] не «erase»). `[+8]=0x400313e8→0x400298c8` = приём из USB (синхронный,
   wait по 0x200), `[+0xC]/[+0x10]=0x400313c0→0x40029758` = передача/очередь (async).
   Flash-таблица — `0x40054374` (+0 = read-диспетчер `0x4002f2f0`, +4 = write
   `0x4002e744`, +8 = erase `0x4002eca4`).
4. **Механизм «тишины»:** ошибки потребителя пишутся в `[ctx+0xE4]` (ctx = `[0x4006E7D0]`).
   Producer-цикл выходит только при **отрицательном** `[E4]` (`cmn r1,#1; ble` @0x40030460),
   а engine-2 возвращает хосту `[E0]`, если `[E4] >= 0` (`ldrpl` @0x40030820). Позитивный
   мусор в `[E4]` → «успех» без записи. Отрицательный → ранний выход из цикла + ошибка
   наружу. Наша картина («100%, per-packet OK, CMD:END OK, флеш не изменился») означает:
   **потребитель ни разу не вернул отрицательный код — либо не получил ни одной записи,
   либо «успешно» прошёл мимо записи.**
5. **Главный подозреваемый (patch-ready): hash-binding gate в `0x4002f804`:**
   `r8 = [0x58struct+1] | [0x58struct+2]` (`orr r8,r2,r1` @**0x4002f850**); при r8≠0
   требуется signature/hash-list (0x4002e4b0 sparse/signature magic `0xED26FF3A` +
   hash-list lookup `0x40036c2c` + SHA `0x4003a2d4` vs `[struct+4]`) — mtkclient этого
   не шлёт никогда.
6. **Конкретный фикс (байты верифицированы из файла):**
   - `0x4002f850`: `01 80 82 e1` (`orr r8,r2,r1`) → `00 80 a0 e3` (`mov r8,#0`) —
     выключает hash-гейт для ВСЕХ разделов (обе ветки: hash-list и inline-digest
     остаются за `beq`).
   - опционально `0x4002e4b0`: `00 00 90 e5` (`ldr r0,[r0]`) → `00 00 a0 e3`
     (`mov r0,#0`) — is_sparse/signature всегда 0 → всегда bulk-путь записи
     (заодно лечит stale-байт `[0x4006E7C8]`).
7. **Самый дешёвый решающий эксперимент:** сессия с `uartloglevel = DEBUG/TRACE`
   (0/1): policy-parse печатает `policy of partition: %s / hash_binding = %d /
   img_auth_required = %d / dl_forbidden = %d` (0x4004e95a/973/986/99e, gate
   `cmp loglevel,#1; bhi`), а потребитель при сбое печатает `image hash binding
   check fail` (0x4004f252), `Security deny [%s] Signature(*.sig) invalid.`
   (0x4004f1c4), `write bulk image() Failed. handle_status(%d)` (0x4004f359) и т.п.

---

## 1. Полная цепочка WRITE-PARTITION (всё proven, кроме помеченного)

```
CMD:WRITE-PARTITION 0x40002034
  parse partition/source_file/pre_erase (0x40001e48)
  policy parse 0x4000217c → 0x4002cf58/0x4002cf68; deny 0x400021a0 (запатчен нами → MOV R0,#0)
  pre_erase=NO ⇒ 0x40002200 bne 0x40002218 — ERASE-ФАЗА ПРОПУЩЕНА (полностью)
  0x400023fc bl 0x4002d970   region-таблица (space_list пуст ⇒ вся партиция от старта)
  0x4000241c bl 0x4002d2cc   storage op
  0x40002440/ac bl 0x4002b874  FILE-SYS-OPERATION запрос к хосту (в логе: key='EXISTS';
                               mtkclient отвечает "OK@0x0" = .sig-файла нет)
  0x400024f0 bl 0x4002ad04   download driver:
      0x4002adb4 snprintf CMD:DOWNLOAD-FILE (fmt 0x4004dd51),
                   packet_length = [0x40067A08+0x14]
      0x4002adbc blx [r4+4]  send XML; 0x4002addc blx [r4] read reply
      0x4002ae28 cmp 'O','K' ← mtkclient ack_value(len); проверяются ТОЛЬКО 2 байта
      0x4002ae60 bl 0x4002c6cc ("PRELOADER")
      0x4002ae68 beq 0x4002ae7c → не-preloader ⇒ ENGINE-2:
      0x4002ae7c mov r0,sb; mov r1,r4(=[sp+0x28]); bl 0x400306ac
```

### 1.1 Engine-2 `0x400306ac` (producer)

```
0x400306b8  ctx-slots: [0x4006E7CC] = fp-0x40; [0x4006E7D0] = sp+4
0x400306e0  bl 0x4002f5f8    open: строит pipeline (буфер ~0x2000+[0x40067A08+0x1c]*2,
                             0x4002f604) и region-список [0x4006E7D4] из 0x58-структуры
0x400306fc  strb 1,[ctx]; [ctx+0x20]=r4(арг0); [ctx+0x24]=r1(арг1 = 0x58-структура!)
0x4003076c  bl 0x400096d8(0x10000, 0x4002ff78, 0, 0x10)  ← регистрация DMA-callback
0x40030778  bl 0x400097e8    (включение канала)
0x4003077c  bl 0x4003010c    DATA LOOP (ниже)
0x400307f4  bl 0x4002f7bc    close = ТОЛЬКО release семафоров (0x40009350 ×6)
0x40030810  bl 0x40008234    commit = bx lr — ПУСТЫШКА
0x40030818  ldr r0,[ctx+0xE4]; cmp r0,#0; ldrpl r0,[ctx+0xE0]  ← маскировка ошибок
```

### 1.2 Data-цикл `0x4003010c` (producer) — протокол обмена УТОЧНЁН

Ключевое открытие: **`0x4003053c` — это ПРИЁМ строки хоста, а не отправка.**
Внутри: приём в буфер `0x4006E800` (через `[0x40054320]` = `0x4002a934` →
`[0x40054330+8]` = `0x400313e8` → `0x400298c8`, транспортный DMA, синхронный),
затем **split строки по '@'** (`0x40008300` — разделитель r3=0x40='@', out:
массив токенов @sp+8, счётчик @sp+4), проверка token0 == "OK", и при 2 токенах
`*arg = token1` (@0x40030604-08) — т.е. **DA парсит число из `OK@<hex>` хоста**.

Отправка DA: `0x400301ec` и `0x40030364`: `blx [0x40054320+4]` (=`0x4002aa14`,
`[0x40054330+0xC]`=`0x400313c0`→`0x40029758`, async) c **`r0=0x40042F0F = "OK\0"`,
r1=3** — вот тот самый «OK», который читает mtkclient `get_response()`. Прогресс
после каждого пакета — `0x40030610`, формат `OK@0x%x` (0x4004f54f), уходит через
тот же `[+4]`.

```
0x4003012c  [sp]   = [0x40067A08+0x14]   (= 0x200000 — СТОКОВЫЙ packet_length, 0x4002f470;
                                     «heapbait поставил 2MB» — на самом деле дефолт DA)
0x40030134  [sp+4] = [0x40067A08+0x1c]   (размер download-буфера по RAM: 0x8000000/
                                     0x4000000/0x1000000 — 0x4002f4b4)
0x4003014c  bl 0x4003053c      READ строки хоста #1 (mtkclient: ack_value(len)="OK@0x80000")
0x4003016c  bl 0x4000aef4      число → u64 → [ctx+0x10/0x14]  = TARGET (= полный len)
0x40030180  target ≤ size партиции (0x58struct+0x50), иначе err 0x40043ac9
0x400301ec  SEND "OK\0"        ← mtkclient resp1 == "OK" (strict!) ✓
LOOP (0x40030310):
  0x4003032c  bl 0x4003053c    READ "OK@0x0" (mtkclient per-chunk ack) → r7 = 0 (не используется
                               кроме checksum-compare)
  0x40030364  SEND "OK\0"      ← mtkclient resp2 ✓
  0x40030398  blx [0x40054320] USB RECV пакета в record-буфер ([record+8]+sl;
                               0x4002a934 → [0x40054330+8], синхронный транспорт)
  0x400303d0  bl 0x40001508    checksum/progress echo (если [0x40067A08]&1)
  0x400303f8  [record+0x4C] += len; [0x4006E7CC+0x18] += len
  0x40030428  [record+0x10] += len   (fill)
  0x40030444  bl 0x40030610    SEND progress "OK@0x<hex>"  ← mtkclient resp3 ✓
  выход из while: sl ≥ [sp+4] (0x8000000) — для наших объёмов не срабатывает
  0x40030474  cmp target(=[ctx+0x10],u64) == accumulated(r8/sb) → EQUAL ⇒ 0x40030494→0x40030288
RELEASE (0x40030294): 0x40009430(record[a4]+0x14, 0) — сигнал потребителю; [a4]^=1
  *** 0x40030250: orrs r4,r7 (target); beq 0x40030498 — при target==0 ВЕСЬ приём
      пропускается: ни одного пакета не читается, record'ы пустые ***
```

Итого producer: принимает всё, отдаёт потребителю **один batch на весь transfer**
(релиз только когда accumulated == target, т.е. в конце), ошибки потребителя
смотрит в `[ctx+0xE4]` (выход только при < 0).

### 1.3 Потребитель `0x4002ff78` (DMA-callback) — ЗДЕСЬ пишется flash

```
0x4002ffa4  0x400093b0(record[a0]+0x14, -1)   ждать producer'а
0x4002ffb0  [ctx+0xE0] < 0 → exit (r1=1 → 0x4002f758(slot,1): release +0x30/+0x7c/+0xa8)
0x4002ffd0  r0 = [record+8] - [record+0xC]; r1 = [record+0xC] + [record+0x10]
            → 0x4002f804(base, len)          ← ОБРАБОТКА+ЗАПИСЬ ЧАНКА
0x4002ffe8  [ctx+0xE4] = ret; ret != 0 → exit (БЕЗ записи остатка!)
0x40030030  [record+0x10] == 0 → exit (ничего не писать, код 0 — «успех»!)
0x40030040  0x40009430(record+0x30, 0) — будить producer; [a0]^=1; ждать дальше
```

### 1.4 `0x4002f804(base,len)` — все гейты на пути к записи

```
0x4002f81c  r4==0 → err 0xC0020007|0x10000 = 0xC0021007
0x4002f840  r0 = [ctx=0x4006E7CC]; r1 = [ctx+0x24] = 0x58-СТРУКТУРА (арг1 engine-2)
0x4002f848  ldrb r0,[ctx+0]     (==1, ставит engine-2)
0x4002f844/4c  r2=[struct+1]; r1=[struct+2]; 0x4002f850 orr r8,r2,r1
            struct+1 = hash_binding, struct+2 = img_auth (заполняет 0x4002cf68:
            0x4002cf88 bl 0x4002cdf4 → strb [r4,#1]; 0x4002cf94 bl 0x4002cf20 → strb [r4,#2];
            0x4002cfa0 bl 0x4002cf34 → strb [r4,#3] = dl_forbidden = DENY-байт;
            флаги берутся из policy-таблицы 0x4005628c (0x4002cbb4, с учётом
            g_oplus_auth_status 0x4005455c @0x4002cbcc и sec_get_seccfg-стейта))
0x4002f858  bl 0x4002e4b0(buf)  = «signature/sparse container?»: *(u32*)buf == 0xED26FF3A
0x4002f864  cmp r8,#0; beq 0x4002f92c      ← БЕЗ hash-политики: сразу писатель
0x4002f860  magic-результат → байт 0x4006E7C8
0x4002f888  [0x4006E730+0x14]=0; [+8]=0; [+0xC]=0; если [0x4006E730+0x10]==0 → 0x4002f92c
0x4002f8dc  bl 0x40036c2c       hash-list lookup; !=0 → err (0x4004f1c4 «Signature(*.sig)
            invalid») + [ctx+0xE8]=err → БЕЗ ЗАПИСИ
0x4002f9ec  offset+len > size партиции → err 0xC0040004 (0x4004f1f2)
0x4002fa38  cmp r8,#0; beq 0x4002fda8      ← r8==0 ⇒ hash-блок (0x4002fa40..0x4002fd9c)
            ЦЕЛИКОМ пропущен (включая SHA 0x4003a2d4 и memcmp vs [struct+4])
0x4002fae4  (в hash-блоке) SHA(buf+consumed, len) → memcmp([struct+4] ptr, 0x20)
            mismatch → «image hash binding check fail» (0x4004f252) + dump
            → err 0xC0020007(+2) → 0x4002fcf8: [ctx+0xE4]=err → БЕЗ ЗАПИСИ
0x4002fda8  ldrb r0,[0x4006E7C8]  (sparse/signature-флаг)
            ==0 → 0x4002fe4c: 0x4002d66c(0x4006E790, buf, len)  ← BULK-писатель
            !=0 → 0x4002fdb4 → 0x4002dd24(0x4006E750, ...)      ← SPARSE-писатель
0x4002fd90  [ctx+0x9C]=0 (сброс consumed), sl += старый consumed
0x4002ff4c  [ctx+0x1C] += [0x4006E750+0x2C] (аккумуляция offsets)
0x4002ff6c  return r6 (успех = 0)
```

### 1.5 Писатели и низший уровень

```
0x4002d5a8 (bulk handle init) → 0x4002d66c:
    цикл по region-списку (0x4002dbdc), на каждый регион:
    0x4002d74c  r3 = [0x40054374+4]; blx r3(offset, len?, buf, [sp]=phys, +4/+8=region)
    → 0x4002e744:
        0x4002e768 bl 0x40008534   ← mov r0,#0; bx lr — КОНСТАНТА 0, всегда != 1
        ⇒ ВСЕГДА 0x4002ea40 → 0x4002eb80(addr, LBA, buf, [fp+8],[fp+0xC],[fp+0x10]=dev)
        0x4002eb80: switch по [dev+0] (тип storage):
            0x10..0x17 → 0x4000f748 (NAND?)
            1..3       → 0x4000cba4/0x4000cbe8 (eMMC path)
            0x31       → 0x40030e40 (LU select: [0x40056A70]=section-0xff; LU из
                          section 0x100..0x102, иначе err 0xC0040060) → 0x40030ec4
            иное       → err 0xC0040009 «unknow or unsupport storage» (0x4004f10d)
        0x40030ec4: cache-clean 0x400003ac; 0x400200ec([0x40056A70], dev, LBA, buf,...)
                    = постановка в очередь UFS; !=0 → 0xC0010001
0x4002e4dc — sparse-писатель (0x4002dbdc parse, те же [0x40054374+4] вызовы)
```

Низкий уровень program-core (вопрос C задачи):
- `0x40029758(r4=ptr, r5=len)`: `0x40027d04(8,0,0,0)` — **ПУСТОЙ СТАБ (`bx lr`,
  байты `1e ff 2f e1` @0x40027d04)**, не UFI-команда; `0x40028030` = `ldr r0,[0x4006E084]`
  (флаг «async-движок инициализирован», ставится в 1 в `0x4002820c` из init `0x400280e0`,
  вызываемого из 0x400312a8/0x4003133c при успешном ветвлении init).
  - `[0x4006E084]==1` → цикл чанков ≤ `0xFC00`: `0x40027e5c(regime=[0x40067978] байт,
    ptr, len, dir)` — публикует дескриптор в очереди `0x4006F18[regime]` (две
    0x10-слот-очереди на regime, ping-pong через байт +0x20), строб `[regime]` →
    doorbell `str r1,[r0<<4 + 0x112009F0]` (0x40027fc0); «занятость» = очередь полна.
  - `!=1` → sync-путь `0x40028c68` (bit4 of 0x11200001) → блок 0x200/0x40,
    `0x400286ac/0x40028884/0x400288e4` + poll `0x40028900` до готовности.
  - В конце: `0x400298b0` poll `0x11200C00` (очередь непуста → wait), затем
    `0x40027d04(8,0,0,1)` — снова пустой стаб.
  - `[0x40067978]` = regime/канал UFS-движка (индекс очереди), НЕ «regime записи».
- Erase `0x400298c8` — тот же движок с dir=1 и **inline-ожиданием завершения**
  (0x40029968 loop на флагах 0x4006E088/0x4006E08C). Program-путь ожидания НЕ имеет —
  завершение возлагено на очередь/IRQ.

## 2. Ответы на пункты A–F

**A. `0x4002aac0`.** Вызываемых ссылок НЕТ (см. TL;DR.1) — условия внутри
(`cmp r2,#0` @0x4002aaf4 → skip; `tst [0x40067A08+8],#2` lock-обрамление) не
достижимы из WRITE-PARTITION. Аргументы (r0=sp+8 buf, r1=0x10) / (r0,r1=аргументы)
— это транспортные send-вызовы, не flash. Слот `[0x40054330+0x10]` валиден, но мёртв.

**B. `0x400306ac`/`0x4003010c`.** Вызова `0x4002aac0` из engine-2 НЕТ (полный
бл-скан). Data-цикл возвращает: при `[ctx+0xE4] < 0` — рано, с кодом наружу;
иначе 0/`[ctx+0xE0]`. Ветка «skip program» — не флаг-переменная, а
**`0x40030250 beq` при target==0** и **выход потребителя при `[record+0x10]==0`/`[E4]!=0`**.

**C. `0x400313c0` → `0x40029758`.** Это транспортный send-op (`[0x40054330+0xC]`),
вызывается из `0x4002aa14`/`0x400306xx`, а не из flash-цепочки. `0x40027d04` —
пустой стаб (не UFI). `0x40028030` — чтение флага `0x4006E084`. `[0x40067978]` —
индекс regime/очереди UFS-движка. Всё описано в §1.5.

**D. `0x4000c210` (наш ACC-pass skip).** Находится в `fcn.4000bb14` — это
**PRELOADER-only engine** (polarity 0x4002ae60-68: не-PRELOADER уходит в
0x400306ac, mtkclient пишет para/seccfg именно туда). Наш патч на
WRITE-PARTITION(para/seccfg) **не влияет и влиять не может** — не источник бага.
(Для чистоты: digest-цепочка 0x4003a2d4/0x40037f70 тоже engine-1-only.)

**E. Подтверждено.** WRITE-PARTITION сам не пишет: record'ы заполняются,
но единственный вызов flash-write (`[0x40054374+4]`) сидит в DMA-callback
`0x4002ff78`→`0x4002f804`; «commit» `0x40008234` — пустышка; `0x4002f7bc` —
только семафоры. Все BL-ссылки: `0x4002aac0` — 0; `0x40030838` ← только
`0x40030b6c` (READ-движок 0x40030c48 ← 0x4002b328: READ-PARTITION 0x400033d0 /
0x40003618 / 0x40005360 — чтение в хост, НЕ write-PARTITION).

**F. `0x4002f7bc`.** Полный дизасм в §1.1-комментарии: 6× `0x40009350(sub-struct)`
(«закрыть» семафоры/каналы sub-объектов ctx: +0x30, +0x7C, +0x14, +0x60, +0xA8,
+0xC4), затем `[ctx]=0`. **UFS-flush там НЕТ.**

## 3. Почему «тихо»: механика скрытия ошибок

| Событие | Кто пишет | Куда | Что видит хост |
|---|---|---|---|
| успешный чанк | consumer 0x4002f804 → 0 | `[ctx+0xE4]=0` | producer продолжает |
| hash/list deny и пр. | consumer | `[ctx+0xE4]=0xC002xxxx/0xC003xxxx` (ОТРИЦАТЕЛЬНОЕ) | producer-цикл выходит на след. проверке (0x40030460), engine-2 возвращает отриц. код → ошибка наружу |
| exit по `[record+0x10]==0` | consumer | ничего | код 0, «успех», ничего не записано |
| позитивный мусор в `[E4]` | — | — | `ldrpl` @0x40030820 подменяет его на `[E0]` → «успех» |

Наша живая картина (100% приём, per-packet OK, CMD:END OK, флеш нетто без
изменений) ⇒ **в цикле не было ни одного отрицательного `[E4]`**. Остаётся два
класса: (i) потребитель получал пустые/нулевые record'ы (handoff/target==0), либо
(ii) прошёл все гейты с r8==0 и «успешно» выполнил запись в участок, который
читается обратно как неизменённый (не туда / не в тот LU), либо (iii) гейт
hash-binding отдавал НЕ-отрицательный код. Все три различаются ОДНОЙ выгрузкой
состояния (§4).

## 4. Решающие live-пробы (дёшево → дорого)

1. **UART DEBUG-сессия** (`daconfig.uartloglevel` → LogLevel DEBUG/TRACE, т.е.
   `SET-RUNTIME-PARAMETER loglevel ≤ 1`). Поймать при WRITE-PARTITION:
   - `==========security policy========== / policy of partition: para /
     hash_binding = %d / img_auth_required = %d / dl_forbidden = %d` —
     **значения hash_binding/img_auth для нашего раздела** (если ≠0 — гейт
     активен, фикс F1 обязателен);
   - при сбое потребителя: `image hash binding check fail`,
     `Security deny [para] Signature(*.sig) invalid.`,
     `Security deny [para] Signature(Entity) invalid.`,
     `write bulk image() Failed. handle_status(%d)`,
     `write sparse image() Failed. handle_status(%d)`,
     `size too large, space small...`,
     `[UFS] err: interface_switch_ufs_section: Invalid UFS LU %d`,
     `[%s]unknow or unsupport storage[%d]!`.
2. **Дамп состояния pipeline сразу после WRITE-PARTITION (та же сессия, до
   следующей команды):** `EXP-PATCH-MEM`/call-примитивом прочитать
   `[0x4006E7CC]` → слова +0x00, +0x18, +0x1C, +0x9C, +0xA0, +0xA4, +0xE0, +0xE4;
   `[0x4006E7C8]`; `[0x4006E7D4]` (region-list head, счётчик); `0x58-структура`
   (указатель в `[ctx+0x24]`): байты +0x00..+0x0F и u64 +0x48/+0x50;
   `[0x40067A08]` слова +0x14/+0x18/+0x1C.
   Интерпретация: `[E4]<0` → hash-гейт (§3); `[record+0x10]==0`/`[ctx+0x9C]==0` →
   handoff/target==0; `[E4]==0` и `[ctx+0x9C]==len` → потребитель «записал» —
   проблема в UFS-слое (тип/LU/очередь).
3. Если (2) укажет на UFS-слой: прочитать `[0x40056A70]` (активный LU) и
   `[dev+0]` (тип storage; dev — второй аргумент chain'а, указатель из
   `[0x40066D80]`-семейства синглтонов).

## 5. Конкретные фиксы (байты из файла проверены)

### F1 — глушить hash-binding gate потребителя (главный кандидат)

| VA | до (файл) | инструкция | после (файл) | инструкция |
|---|---|---|---|---|
| `0x4002F850` | `01 80 82 e1` | `orr r8, r2, r1` | `00 80 a0 e3` | `mov r8, #0` |

Эффект: r8==0 всегда ⇒ `beq 0x4002f92c` (hash-list ветка мимо) и
`beq 0x4002fda8` @0x4002fa38 (inline-SHA/digest-блок 0x4002fa40–0x4002fd9c
пропущен целиком) ⇒ любой чанк идёт в bulk-писатель `0x4002d5a8→0x4002d66c→
[0x40054374+4]`. Данные пишутся as-received. Обе точки использования r8 —
только эти два `cmp/beq`; иных читателей r8 в функции нет (проверено по дизасму
0x4002f804–0x4002ff74).

### F2 — эквивалент F1 двумя точками (если хочется точечнее)

| VA | до | после |
|---|---|---|
| `0x4002F844` | `01 20 d1 e5` `ldrb r2,[r1,#1]` | `00 20 a0 e3` `mov r2,#0` |
| `0x4002F84C` | `02 10 d1 e5` `ldrb r1,[r1,#2]` | `00 10 a0 e3` `mov r1,#0` |

### F3 — принудительный bulk-путь (лечит и stale sparse-флаг)

| VA | до | после |
|---|---|---|
| `0x4002E4B0` | `00 00 90 e5` `ldr r0,[r0]` | `00 00 a0 e3` `mov r0,#0` |

`0x4002e4b0` больше нигде не вызывается (единственный BL — 0x4002f860) — патч
локален. Побочный эффект: если когда-нибудь понадобится писать НАСТОЯЩИЙ sparse-
образ через этот DA — патч придётся снять.

### F4 — host-side (если разведка покажет, что дело в числах OK@)

Не менять семантику первых двух ack'ов: DA читает строку №1 как TARGET
(`0x4003014c`→`0x4003016c`), и при **target==0 весь приём пропускается**
(0x40030250). Порядок mtkclient-строк обязан быть:
`ack_value(len)` (съедается DOWNLOAD-FILE-check, проверяются только 'O','K')
→ [DA читает её же как target? нет: DA читает СЛЕДУЮЩУЮ строку] …

Точная калька обмена (proven по коду):
1. DA ← `OK@<len>` (DOWNLOAD-FILE ack);
2. DA читает строку №1 = **следующая** TX хоста и парсит её число в TARGET;
3. DA шлёт `"OK\0"`;
4. цикл: DA читает `OK@0x0`, шлёт `"OK\0"`, принимает пакет, шлёт `OK@0x<pos>`.
⇒ mtkclient'у НУЖНО, чтобы между `ack_value(len)` и первым пакетом хост послал
ровно ОДНУ строку `OK@<что-то != 0>` — текущий `upload()` шлёт `ack_value(0)`,
и если тайминг сложится так, что именно она станет строкой №1, transfer молча
не состоится. **Надёжный host-fix: в `upload()` первый in-loop ack слать как
`ack_value(length)` (не 0), а последующие — `ack_value(0)`** — тогда target
сойдётся с accumulated в конце и при любом тайминге ≠ 0. (Это дешёвое
изменение стоит сделать в любом случае — оно устраняет целый класс race'ов.)

## 6. Что НЕ трогать

- `0x4002f7bc`, `0x40008234` — не «потерянный flush», патчить бессмысленно.
- `0x4002aac0` — мёртвый код, патчи туда не работают (существующие патчи набора
  его не трогают — ok).
- `0x4000c210`/HACC-патчи — нужны для PRELOADER-путей и security-классификации,
  к данному багу отношения не имеют.
- `0x40008534` (RET0-стаб) — НЕ патчить «наоборот»: он consciously возвращает 0,
  и это уводит `0x4002e744` на рабочий dispatch-путь `0x4002eb80`.

## 7. Рекомендуемый порядок работ

1. F4 (host-fix первого ack → `ack_value(length)`) — 2 строки в `xml_lib.upload`,
   проверить WRITE-PARTITION para без DA-патчей. Если помогло — причина была
   target==0 race.
2. Если не помогло: DEBUG UART-сессия (§4.1) + дамп ctx (§4.2).
3. По результату: F1(+F3) через `patch_mem` ДО команды записи, повторить para,
   затем seccfg (существующий набор патчей сохранить).
4. Контроль: same-session readback + fresh-session readback (как в `v6.py`
   seccfg-плане).

## 8. Неопределённости (честно)

- Значения `hash_binding`/`img_auth` в рантайме для para/seccfg не считаны —
  статически они выводятся из policy-таблицы + `g_oplus_auth_status` +
  sec_get_seccfg-классификации; точные байты 0x58-структур (+1/+2) в нашей
  сессии не дампились.
- Не прослежен до конца выбор «bulk vs sparse» при stale-байте `0x4006E7C8`
  (ветка 0x4002fdb4 → 0x4002dd24 → 0x4002de38 switch по mode хэндла) — возможен
  ещё один тихий skip внутри sparse-писателя на не-sparse данных.
- Внутренности `0x400200ec` (UFS queue submit) и поведения очереди/IRQ не
  трассированы; завершение program-транзакции возлагается на асинхронный движок
  (флаг 0x4006E084 = 1 в рантайме, bit6 0x11200001 = 1 по live-пробе).
- Точная строка, которую DA шлёт между DOWNLOAD-FILE-ack и первым пакетом,
  восстановлена из кода («OK\0» через `[0x40054320+4]` @0x400301ec/0x40030364);
  соответствие живому логу (rxleft=None, strict `resp=="OK"`) — согласовано, но
  побайтового UART-лога обмена в этой заметке нет.
