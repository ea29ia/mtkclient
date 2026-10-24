# RE: почему CUSTOMMEMW не пишет в RGU 0x10007024 и рабочий способ записи

Date: 2026-10-24. Контекст: realme RMX3630 (MT6789), OPLUS DA2, mtkclient-форк
`/home/musin/mtkclient`. Shellcode-расширение `mtkclient/payloads/da_xml.bin`
(16652 Б, **ARM32/Thumb**, патчится в рантайме DA2 — `patch()` в
`mtkclient/Library/DA/xmlflash/extension/v6.py:224`, 0x11-маркеры → адреса DA2).
Компаньоны: `re-da2-bootmode-reboot.md`, `re-da2-readregister.md`.

Статусы: **[proven]** = байты прочитаны/дизасм+эмуляция приведены; **[inferred]** = помечено.

---

## TL;DR

1. **CUSTOMMEMW не пишет в память ВООБЩЕ — это no-op [proven].** Его handler
   (Thumb @0x448 в da_xml.bin) читает с хоста адрес (8 Б), длину (4 Б) и данные
   (≤4 Б) в **собственный стек**, причём данные кладёт **в тот же буфер, где лежал
   адрес** (затирает его), и возвращается с `r0=0` (= OK). В функции нет **ни одной**
   store-инструкции в целевой адрес. Поэтому `custom_write()` возвращал True,
   а 0x10007024 оставался 0x24002000. Раньше ошибочно списывали на «APB bridge
   роняет побайтовую запись» (ai.txt §1) — это неверно: запись не происходит даже
   на уровне CPU.
2. **Рабочий способ [proven]: `CMD:CUSTOMREGW`** (mtkclient
   `custom_writeregister`, v6.py:1025). Его handler (Thumb @0x48c) читает 4 Б
   адреса + 4 Б значения и делает **прямой `str r0,[r1]`** — без единой проверки
   адреса/диапазона. Чтение-модификация-запись ниббля:
   `custom_readregister(0x10007024)` → `val = (val & ~0xF) | nibble` →
   `custom_writeregister(0x10007024, val)`.
3. RGU-регистр 0x10007024 **не защищён**: сам DA2 пишет его прямыми `str` без
   всяких unlock-последовательностей (re-da2-bootmode-reboot §1.1/§4.3 —
   0x4002a4c8 `bfi`, 0x4002a4e4 `bic 0xff0`, 0x4002a5e8 `orr 0xE`,
   0x4002a728 и др.) [proven]. Проблема была только в сломанном CUSTOMMEMW.
4. Готовый скрипт: `docs/notes/rgu_nibble_test.py` (v3) — пишет через
   `custom_writeregister`, fallback — `heapbait.patch_mem`.

---

## 1. Архитектура shellcode da_xml.bin [proven]

Файл: ARM-заглушка из 2 слов (`add r3,pc,#1; bx r3`) → далее **Thumb**-код.
Вход `init` @0x8: получает контекст, затем **12 блоков регистрации** (0x12–0xc8):
каждый блок = `ldr r0,=имя; ldr r1,=perm("1"@0x3a9f); ldr r2,=handler; blx [r5]`,
где `[r5]` = указатель на DA2-регистратор (`0x11\x11\x11\x11`-маркер @0x3ee0,
заменяется `patch()` на адрес `register_xml_cmd` DA2). Имена — указатели на
строки `CMD:...` в хвосте файла (0x3a68–0x3b29); все вычисления позиционно-независимы
(`ldr lit` + `add rX,pc`).

Полная таблица (получена **эмуляцией init под Unicorn** с подменой регистратора —
устраняет неоднозначность ручного Align(PC,4)) [proven]:

| Команда | строка @ | handler (Thumb) |
|---|---|---|
| CMD:CUSTOMACK | 0x3aef | 0x4c6 |
| CMD:CUSTOMREGW | 0x3a90 | **0x48c** |
| CMD:CUSTOMREGR | 0x3b1d | 0x3d4 |
| CMD:CUSTOMMEMR | 0x3aa1 | 0x370 |
| **CMD:CUSTOMMEMW** | 0x3abe | **0x448** |
| CMD:CUSTOMSTORAGE | 0x3add | 0x350 |
| CMD:CUSTOMRPMBK | 0x3a70 | 0x668 |
| CMD:CUSTOMRPMBP | 0x3afd | 0x694 |
| CMD:CUSTOMRPMBI | 0x3a80 | 0x60c |
| CMD:CUSTOMRPMBR | 0x3b0d | 0x4e4 |
| CMD:CUSTOMRPMBW | 0x3acd | 0x574 |
| CMD:CUSTOMSEJ | 0x3ab0 | 0x134 |

Протокол handler'ов: DA2-диспетчер принимает XML, отвечает OK, затем handler
тянет сырые DATA-чанки хоста через helper `H(dst, countptr, [sp]=maxlen)`
(`blx [r4]`, `[r4]` = recv-функция контекста, `[r4+4]` = send). mtkclient
соответствие: `xsend(data=addr, is64bit=True)` → пакет 8 Б ✓, `xsend(len)` → 4 Б ✓,
`xsend(data)` → `len(data)` Б ✓ (xml_lib.py:251).

## 2. CMD:CUSTOMMEMW @0x448 — handler-пустышка [proven]

```
0x448  push {r4-r7,lr}; r7=sp+0xc; str r8,[sp,#-4]!; sub sp,#0x10
0x452  r4 = ctx (arg0);  r8 = sp+8        ; буфер "адрес" (8 Б)
0x458  strd r0,r0,[r8]                    ; обнулить
; --- call1: H(dst=sp+8, countptr=sp, [sp]=8, [sp+4]=0)  -> АДРЕС (8 Б, u64)
0x46a  mov r0,r8; mov r1,r6(=sp); [sp]=8; blx [r4]
; --- call2: H(dst=sp+4, countptr=sp, [sp]=4)            -> ДЛИНА (4 Б)
0x476  mov r0,r5(=sp+4); mov r1,sp; [sp]=4; blx [r4]
; --- call3: H(dst=sp+8 (!!!), countptr=sp+4, [sp]=4)    -> ДАННЫЕ (≤4 Б)
0x47e  mov r0,r8      ; dst = ТОТ ЖЕ буфер адреса!
0x480  mov r1,r5
0x482  blx [r4]       ; данные затирают младшие 4 Б адреса
0x484  add sp,#0x10; ldr r8,[sp],#4; pop {r4-r7,pc}   ; КОНЕЦ — store НЕТ
```

Всего 0x42 байта, **ни одного `str`/`strb` в память по адресу из аргументов**.
`strd`@0x45c пишет только в собственный стек. Функция возвращает 0 (успех) →
DA отвечает OK → `custom_write()` возвращает True. Наблюдение «True, но регистр
не изменился» полностью объясняется.

Следствия/ответы на вопросы задачи:
- **is64bit ни при чём**: MEMW и MEMR читают адрес одинаково — 8 байт
  (`is64bit=True` с обеих сторон корректен) [proven].
- **Ограничений адресов нет и в MEMR** (потому чтение BROM 0x0 и RGU работало):
  ни DRAM-only проверки, ни SEC-зон, ни forbidden-таблиц — их просто никто не
  писал [proven по дизасму всех трёх mem/regr-хендлеров]. Единственные капы:
  MEMR — длина ≤0x20000, REGR — ≤0x2000 dword'ов.
- Даже если бы store был, call3 с max=4 прочитал бы только первые 4 Б данных
  (остаток длины ушёл бы в поток как мусор — desync). Т.е. handler сломан дважды.
- **CUSTOMMEMR @0x370** (для сравнения) [proven]: recv 8Б addr → 4Б len
  (кап 0x20000) → `ldrd r1,r0,[r5]` → `bl 0x3800` — байт-копия
  `ldrb [r1],#1 / strb [ip],#1` (**прямой CPU-доступ**, используется только
  младшее 32-бит слово адреса — addr_hi отбрасывается, для <4 ГБ неважно) —
  затем send. Чтение работает с любого отображённого VA.

## 3. CMD:CUSTOMREGW @0x48c — рабочий примитив [proven]

```
0x48c  push {r4-r7,lr}; r7=sp+0xc; str fp,[sp,#-4]!; sub sp,#0x10
0x496  r4=ctx; [sp+0xc]=0; [sp+8]=0
; --- call1: H(dst=sp+0xc, countptr=sp+4, [sp]=4) -> АДРЕС (4 Б)
; --- call2: H(dst=sp+8,   countptr=sp+4, [sp]=4) -> ЗНАЧЕНИЕ (4 Б)
0x4b6  ldr r0,[sp,#8]      ; value
0x4b8  ldr r1,[sp,#0xc]    ; addr
0x4ba  str r0,[r1]         ; *(u32*)addr = value  <- ПРЯМОЙ STORE
0x4bc  movs r0,#0; ...; pop -> ret 0
```

Проверок адреса нет. mtkclient `custom_writeregister(addr, val)` шлёт
`xsend(addr)` и `xsend(val)` — оба 4 Б LE (xml_lib.py:251, is64bit=False) —
ровно то, что ждёт handler. Парный **CUSTOMREGR @0x3d4** [proven]: recv 4Б addr +
4Б count (кап 0x2000 dword), затем цикл `ldr r1,[addr + i*4]` в стейдж-буфер и
send(count*4) — прямые CPU-загрузки, тоже без проверок.

**Происхождение и режим CPU**: DA2 на MT6789 исполняется с включённой MMU, но
периферия (RGU 0x10007000-блок) отображена **identity** — DA2 сам делает
`ldr/str` по 0x10007024 в своих reboot-путях (см. §5), и CUSTOMMEMR уже читает
0x10007024 согласованно (0x24002000) на живом устройстве. Значит `str` из REGW
попадёт в тот же регистр. [proven по поведению чтения + по коду DA2; сама запись
REGW на железе — финальная проверка скриптом]

## 4. Прочие команды расширения (кратко)

- **CMD:CUSTOMSEJ @0x134** [inferred, механика по прологу]: читает 0x20 Б
  (ключ/nonce) + 8 Б (длина), стек 0x5b4, обнуляет q8, далее SEJ-шифрование
  (hw Security Engine AES). К записи в RGU отношения не имеет.
- **CMD:CUSTOMSTORAGE @0x350 / CUSTOMRPMB\* @0x4e4/0x574/0x60c/0x668/0x694 /
  CUSTOMACK @0x4c6** — RPMB/storage-обёртки вокруг указателей из 0x22/0x33/0x44-
  маркеров (`patch()`); к RGU не относятся.
- **Нативные CMD:READ/WRITE-REGISTER DA2 (0x40006eec/0x4000700c)** — мертвы:
  auth-гейты 0x40010fb0/0x40010fb8 — заглушки `mov r0,#0` → всегда
  "R/W on this address is forbidden" (re-da2-readregister.md §5) [proven].
  Потому и нужен shellcode-путь.

## 5. Как RGU пишет сам DA2 (item 4) [proven, сводка из re-da2-bootmode-reboot]

Все пути — прямые `str` по 0x10007000-блоку, **unlock-последовательностей
(RGU_WPSSR/RGU_SPF и т.п.) нет нигде**:

| VA | Что пишет |
|---|---|
| 0x4002a4c8 | SET-BOOT-MODE FASTBOOT: `ldr r1,[0x10007024]; bfi r1,r2,#0,#4 (r2=3); str` |
| 0x4002a520 | nibble-setter: `ldr r2,[0x10007024]; bic r2,#0xff0; orr r2,r2,r0,lsl#4; str` — пишет биты **[7:4]**, не [3:0]! |
| 0x4002a4e4 | reboot-подготовка: `ldr; bic #0xff0; str` (биты[3:0] сохраняет) + `str 0,[r4,#-4]` (0x10007020=0) + bits[31:29]=4 |
| 0x4002a5c8/0x4002a53c | RGU mode-config: `0x10007000 |= 1 | 0x22000000` |
| 0x4002a710 | `0x10007004 = (3<<11)|8` (WDT timeout) |
| 0x4002a728 | `0x10007008 = 0x1971` (WDT kick/restart-ключ) |
| 0x4002a5e8 | EDL: `0x10007024 |= 0xE` |

Важно: **0x4002a520 — НЕ тот ниббль**, что нужен для boot-mode (он ставит
bits[7:4]); boot-nibble live в bits[3:0] (LK читает `& 0xF`, FASTBOOT=3).
Поэтому EXP-CALL-FUNC на 0x4002a520 (вариант (г) из постановки) для нашей
задачи не годится вдвойне: (1) heapbait-хендлер EXP-CALL-FUNC парсит только
`da/arg/address`, r0 не передаётся (комментарий в heapbait.py:597) [proven по
коду форка]; (2) даже с r0=nibble он писал бы не в тот ниббль.

## 6. ИТОГ: рабочий рецепт записи ниббля в 0x10007024 из DA2-сессии

**Основной (proven-по-дизасму, 3 вызова уже существующего API):**
```python
val = loader.xmlft.custom_readregister(0x10007024, 1)   # CUSTOMREGR, прямой ldr
val = (val & ~0xF) | 3                                   # FASTBOOT nibble
loader.xmlft.custom_writeregister(0x10007024, val)       # CUSTOMREGW, прямой str
# verify:
assert (loader.xmlft.custom_readregister(0x10007024, 1) & 0xF) == 3
```

**Fallback (inferred, high):** `loader.xmlft.heapbait.patch_mem(0x10007024,
pack('<I', val))` — EXP-PATCH-MEM уже писал в VA-пространство DA2
(0x4005455c); RGU в том же пространстве. Проверить, если REGW недоступен.

**Не использовать:** `custom_write`/CUSTOMMEMW (no-op, всегда True);
`call_func(0x4002a520)` (r0 не передаётся + не тот ниббль);
нативные CMD:WRITE-REGISTER (auth-заглушка → всегда forbidden).

## 7. Вариант (а): починка CUSTOMMEMW в da_xml.bin [proven-байты, опционально]

Handler @0x448 (слот 0x448..0x48a, 0x42 Б до REGW @0x48c) можно заменить на
корректную версию для **4-байтовых** записей (адрес — младшие 32 Б, что
покрывает всю периферию):

```
f0b5 03af 86b0 0446 6e46 0020 0190
0820 0090 3146 04a8 2268 9047          ; recv 8B addr -> [sp+0x10]
0420 0090 3146 03a8 2268 9047          ; recv 4B len  -> [sp+0xc]
0020 0190 0420 0090 3146 6846 2268 9047 ; recv 4B data -> [sp]
0098 0499 0860                          ; *(u32*)[sp+0x10] = [sp]
0020 06b0 f0bd                          ; ret 0
```

(дизасм-контроль пройден: push/sub/mov/3×recv-последовательности/`str r0,[r1]`/pop).
Ограничение: data >4 Б не consum'ится → desync потока; для register-записей
неактуально, но **в общий payloads/da_xml.bin патчить не стоит** — REGW
полностью закрывает задачу. Оставлено здесь как референс.

## 8. Сводка proven / inferred

- proven: таблица регистрации 12 команд (Unicorn-эмуляция init); карта handler'ов
  MEMW@0x448 (no-op, данных→в буфер адреса, store отсутствует), MEMR@0x370
  (байт-копия 0x3800, прямые ldrb), REGW@0x48c (`str r0,[r1]`), REGR@0x3d4
  (цикл ldr); согласованность is64bit/4Б с xsend(); отсутствие любых
  адресных проверок; no-unlock RGU в DA2 (по компаньон-записке); 0x4002a520
  пишет bits[7:4].
- inferred: семантика CUSTOMSEJ (по прологу); работоспособность patch_mem на
  IO-адресе (по аналогии с 0x4005455c); финальное подтверждение REGW-записи на
  живом устройстве (скрипт v3).
