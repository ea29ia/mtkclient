# RE: downstream-консьюмеры boot-mode слотов в preloader, ATAG-строение (RMX3630 / MT6789)

Date: 2026-10-24. Target: `IMAGES/preloader_k6789v1_64.bin` (390868 B, ARM32/Thumb, PIC).
Маппинг **VA = file_offset + 0x200F10** (proven, см. re-preloader-daa-lk.md).
Метод: линейный sweep capstone по всему бинарнику с резолвом pc-relative LDR → литерал → значение
(все xrefs ниже — proven как «instruction по этому VA загружает литерал, содержащий ровно это слово»;
семантика каждого сайта — proven там, где приведён дизасм, иначе inferred).

Контекст из re-oplus-preloader-handshake.md: диспетчер AT-токенов (0x228C60–0x228EF2,
`oplus_usb_handshake`) пишет: **0x2F4264 ← boot mode** (0x63=FASTBOOT @0x228F6E,
4/5/6 = factory/meta, 0=NBOOT ack), **0x2F4260 ← 5** (NBOOT), **0x2F4244 ← meta_com_id**,
**0x2F4248 ← meta_log_disable**, **0x2F4240 ← 1/2** (main, до/после 0x231594).

---

## 1. Xrefs: кто читает слоты ПОСЛЕ диспетчера

Полный список pc-relative загрузок литералов с этими значениями (linear sweep, proven):

### 0x2F4264 (boot_mode)
| VA сайта | Функция (начало, inferred по push {..,lr}) | Роль |
|---|---|---|
| 0x228E82 / 0x228EB4 / 0x228EC8 / 0x228EEE / 0x228F2E / 0x228F6C | сам диспетчер 0x228C60–0x228EF2 | источники записи (NBOOT/META/FACTORY/FASTBOOT ветки) |
| **0x232F30** | **0x232EDC — main boot-to-LK путь** (caller 0x232F9C → 0x23238C) | `ldr r0,[r0]; cbnz r0, 0x232F6E` — **если *0x2F4264 != 0, пропускает цикл ожидания** (battery-inserted / USB-handshake retry loop, строки 0x24FBBB `%s Wait for battery inserted...`, 0x24C358) |
| **0x231E38 (литерал в пуле 0x231E30–0x231E48)** | **0x231694 — builder boot-tags/ATAG-структуры** | читается в конструктор (см. §2) |
| 0x22539C (пул 0x225398) | 0x225150 (caller 0x231C94) | см. §2.3 |
| 0x232414 (пул 0x232400) | 0x23238C | ветка логирования/meta (см. §2.2) |
| 0x232FE8 (пул 0x232FD8) | 0x232EDC | вторая ссылка внутри main boot пути (пул смешан со строками battery/bc_pre_init) |
| 0x236EB4 (пул 0x236E??) | 0x236B90 | см. §1.1 |
| 0x205C3C (пул 0x205C38) | 0x205B3C (caller 0x2327EA) | см. §1.1 |

### 0x2F4260 (NBOOT slot)
| VA сайта | Роль |
|---|---|
| 0x228ECE | диспетчер, запись 5 (NBOOT) |
| 0x21F1B8 / 0x21F298 (ф-и 0x21F1B0/…) | inferred: ранний boot-path код (не декодирован детально) |
| 0x225AD8 (пул, ф-я 0x2257EC) | inferred |
| 0x230154 (0x230144), 0x2315B4 (0x231594) | 0x231594 = security/gate-функция, вызывается из main @0x228852 ДО handshake (см. §1.2) |
| 0x2323BA (0x23238C), 0x232B76 (0x232908) | boot-flow |
| 0x231E34 — **литерал в пуле builder'а 0x231694** | см. §2 |

### 0x2F4244 (meta_com_id)
Только 3 сайта: 0x228E9A / 0x228F14 (диспетчер, запись) и **0x231E3C — пул builder'а 0x231694**.
⇒ **meta_com_id потребляется ТОЛЬКО builder'ом boot-tags.**

### 0x2F4248 (meta_log_disable)
2 сайта: 0x228E62 (диспетчер, запись) и **0x231E44 — пул builder'а 0x231694**.

### 0x2F4240 (main flag 1/2)
| VA сайта | Роль |
|---|---|
| 0x228BA8 | диспетчер-регион: чтение в начале oplus_usb_handshake |
| 0x228858 / 0x22885E | **main 0x2287xx**: после `bl 0x231594` (0x228852): cbz → **0x2F4240 = 2** (0x228858+movs 2), иначе **0x2F4240 = 1** (0x22885E+movs 1) — proven |
| 0x239172 | `ldr r0,[pc]; movs r1,#2; str r1,[r0]` — внутри `oplus_usb_handshake` (0x23913C): **0x2F4240 = 2** — proven |
| 0x2323DC | 0x23238C — чтение `ldr r0,[r0]; cmp r0,#1` (гейт: если 0x2F4240==1 и *(g_ptr)==1 → лог+вызов 0x239820) |
| 0x225398 | пул 0x225150 |
| 0x239244 | пул oplus_usb_handshake (boot-params, см. re-preloader-daa-lk.md §3.1) |

### 1.1. Прочие читатели 0x2F4264 (0x236B90, 0x205B3C) — briefly
- **0x205B3C** (caller 0x2327EA): лог-запись «серийный/boot storage» выбора — читает 0x2F4264 в пуле
  рядом с литералами `0x62645336…` (строки). Семантика: slot-selection/logging, **не влияет на выбор fastboot**
  (inferred, поверхностно декодирован: запись + сравнение типов storage, вызов 0x205AE8 с r0=1/2).
- **0x236B90**: содержит хэндл-таблицу (ветвление по r1 vs 3, `movw r1,#0x16D/0x16F`, mla-арифметика) —
  inferred: вспомогательный lookup (debug/log-fmt), не boot- decision.

### 1.2. main-гейт 0x228852 — «0x2F4240 = 1/2» (proven)
main (0x2287xx): `bl 0x231594` (0x228852); 0x231594 — security-check обёртка (лог + bfi-флаг в
глобале 0x2F31?? + ветвление по `bl 0x207178` ⇒ reset_reason 1/2 → `bl 0x22F0BC(0x122/0x126, …)` —
inferred: msec_init/DP-логика). Возврат !=0 → `*(0x2F4240)=2`, иначе `=1` (0x228858–0x228862).
Затем 0x2F4240 читается диспетчером (0x228BA8) и в 0x23238C (гейт `==1 && *(ptr)==1` → лог + 0x239820).
**0x239820 = «reboot в meta/на следующий boot» хелпер**: сохраняет r0 в глобал [0x25F03C], потом
конфигурирует контроллер (0x2245E0/C0/C8/D0 — watchdog/RTC-стиль, `orr r2,r2,#7` — включение таймера,
lit 0x11003000 @0x2398B4 — inferred: топ-регионы 0x1100xxxx = topckgen/RTC, «перезагрузка с метаданными»).
⇒ 0x2F4240=1 + доп. условие = preloader сам решает уйти в reboot/meta-режим (путь factory «meta boot»), не fastboot.

---

## 2. Как preloader строит ATAG / boot-tags

### 2.1. Главный builder: **0x231694** (вызывается единственно из 0x2323CC)

Все значения proven из дизасма:

1. **База структуры**: `r6 = *(g_ptr1)` где g_ptr1 = глобал @**0x2F3160** (r6=[pc,#0x2FC] @0x23169E
   → литерал; тот же 0x2F3160 читают десятки сайтов — это указатель на **platform boot-params /
   boot-tag area**, inferred: SRAM-структура, совместно используемая с LK). Поля заполняются по
   смещениям от неё (`str.w r1,[sb,#0x14]` и т.д., sb = r0 = аргумент-структура).
2. **Порядок заполнения (частично proven)**:
   - `+0x10 = 0x10`, `+0x00 = 0x10`, `+0x20 = 0x10` (размеры/маркеры);
   - `+0x28 ← *(0x2F4264)` — **boot mode из слота диспетчера попадает в структуру по смещению +0x28**
     (0x2316D2 `ldr r0,[r5]`, r5→литерал 0x231E38=0x2F4264; 0x2316D4 `str.w r0,[sb,#0x28]`) — **proven**;
   - далее пул 0x231E30–0x231E48 даёт: 0x2F4260, 0x2F4264, 0x2F4244, 0x2F4240, 0x2F4248,
     строку `"\n log_port %d log_baudrate %d log_enable %d log_…"` (0x24F110), 0x2F3160 —
     т.е. builder печатает boot-статус и читает ВСЕ пять слотов (частично inferred: точные
     смещения назначения каждого — только 0x2F4264 proven в +0x28);
   - функция логает (`"\n%s boot_tag size = 0x%x"` @0x24F1F7, `"\n%s boot_tag oversize!"` @0x24F211 —
     proven, литералы в её пуле 0x231E88/0x231E90) и собирает TLV-массивы (`0x58B0`/`0x5888`-байтовые
     копии, циклы 0x2317B4/0x2317DA/0x231818 — inferred: сериализация boot-tag записей, элемент 0x18/0x10 B).
3. **Вызывающий контекст 0x23238C** (proven):
   - 0x23239A `bl 0x2394F4`; 0x2323A0 `bl 0x239504` (пара get-функций: 0x239504 — вызывает 0x22F0BC-стиль
     провайдеры, inferred: получает «boot reason/мета» из глобалов);
   - результаты кладутся по смещению литерала 0x231E48/0x2F3160-стиля (`str r1,[r0,r3]` @0x2323AE —
     запись в ту же boot-params область);
   - 0x2323C6 печать; **0x2323CC `bl 0x231694`** (builder); 0x2323D0 `bl 0x231F28` — большой switch по
     `tbh`-таблице (0x231F60) с ветками 0x232176/0x232296 — inferred: dispatcher boot-tag типов
     (вторичный: разбор/добавление отдельных тагов по boot reason);
   - 0x2323D4–0x2323E2: `ldr r0,[0x2F4240-pool]; cmp r0,#1; ldr r0,[pool 0x2F4240]; cmp r0,#1; beq` —
     двойной гейт; **при выполнении: печать + `bl 0x239820`** (0x2323F0) — reboot/лог-хелпер (см. §1.2).

### 2.2. Кто вызывает 0x23238C (proven по bl-графу)
Единственный caller — **0x232F9C** внутри **0x232EDC** (main boot-to-LK путь). Контекст 0x232F30–0x232F9C:
```
0x232F30 ldr r0,[0x2F4264]; cbnz r0, skip          ; если boot-mode != 0 — НЕ ждать battery/USB
0x232F36 bl 0x2071DC ... bl 0x23E0C8               ; цикл ожидания (battery/charge), bed: 0x22F30C, 1s ticks
0x232F6E movs r0,#1; bl 0x2060E4                   ; (inferred: platform_init_final/штатный переход)
0x232F8C bl 0x235888; bl 0x232DBC; bl 0x232E1C; bl 0x232E7C   ; финализация (inferred: таймеры/лог/irq)
0x232F9C bl 0x23238C                               ; ← СТРОИМ boot-tags/ATAG
```
⇒ **Порядок proven: boot-tags строятся в последнюю очередь перед прыжком в LK, и 0x2F4264=0x63 в них попадает.**

### 2.3. «boot to LK by ATAG» (proven)
Строка `"\n%s boot to LK by ATAG reason=%d addr=0x%x\n"` @**0x24F780**, её литерал в пуле @**0x232408** —
внутри ветки 0x23238C/0x232400-пула (та же функция, альтернативная ветка логирования при
`*(0x2F4240)==1`-стиле гейта). Параметр `reason` — inferred: значение boot reason из 0x239504-пары.
Пул 0x232400 содержит 0x2F4260, 0x2F3164 (второй глобал-указатель), 0x24F780, 0x24F01D `[PLFM]`, 0x2F4240, 0x2F4264.

### 2.4. «pl-boottag» валидатор (proven места, inferred семантика)
Строка `pl-boottag` @0x24FB18 и `pl_boottag_res:0x%x, should:0x%x, assert!` @0x24FB26; литерал
`pl-boottag` в пуле @0x232E68 → ф-я 0x232908-региона (там же читатель 0x2F4260 @0x232B76).
⇒ preloader строит **именованный таг «pl-boottag»** и ассертит его содержимое против ожидаемого
(inferred: это и есть механизм, которым preloader передаёт LK структурированный boot-tag блок).

### 2.5. brom_meta_mode 1/0x64 («skip handshake») — куда пишут
Из re-oplus-preloader-handshake.md: brom_meta_mode (r4, из BROM-регистров при входе) 1 →
`%s BR META BOOT`, 4 → `%s BR FACTORY BOOT`, 5 → …; значения **1 и 0x64 пропускают USB-handshake**.
В бинаре пути skip (proven места ветвлений, inferred семантика): при brom_meta_mode ∈ {1,0x64}
диспетчер не запускает AT-диалог, а сразу пишет **0x2F4264 ← 1** (META) / 0x2F4240-путь — т.е.
«skip handshake» эквивалентен бриджу «boot mode = META(1)», а НЕ новому виду тага: пишутся те же
слоты 0x2F4260/0x2F4264/0x2F4244, которые дальше потребляет builder 0x231694.
(0x64 = 100: в дизасме диспетчера отдельная ветка `cmp …,0x64` не найдена proven-уровнем —
inferred из прежней заметки; пишущий сайт не локализован, помечаю как **unresolved**.)

### 2.6. Что реально попадает в таги (итог §2)
- **boot mode (0x63 при FASTBOOT-токене) — ДА**, в поле структуры по +0x28 (proven), плюс печатается/валидится как «pl-boottag».
- **reboot reason — ДА**, отдельным параметром (`boot to LK by ATAG reason=%d addr=0x%x`; источник —
  get-пара 0x2394F4/0x239504; типовая MTK семантика: RGU/PMIC status — inferred).
- **meta_com_id / meta_log_disable / nboot(0x2F4260) / main-flag(0x2F4240)** — читаются builder'ом
  (пул proven), распределение по полям — inferred.
- **адрес ATAG для LK**: строка говорит «boot to LK by ATAG ... addr=0x%x» — т.е. preloader передаёт
  LK указатель на ATAG-структуру (inferred: в r0/r2 при прыжке; конкретный регистр не доказан).

---

## 3. HW-регистр reboot-reason / boot-info в preloader

1. **0x10007024 (RGU boot addr / sram bootor flag)**: все ссылки в preloader — **чтение** в
   RGU-драйвере 0x23DF10–0x23E448 (0x23DF1C/0x23DF34/0x23DF4C/0x23DF64/0x23DF7C/0x23DF94/0x23DFAC/
   0x23DFBC читают 0x10007024; 0x23DFD8+ читают 0x10007000) — **proven (только ldr-сайты; ни одного
   str в 0x10007024 не найдено sweep'ом)**. Т.е. **preloader НЕ пишет boot-mode в HW-регистр 0x10007024.**
2. **0x10007000** встречается ещё как **данные**: @0x225192 (ф-я 0x225150) литерал 0x10007000 кладётся
   внутрь заполняемой структуры (`mov.w sb,#0x10200000; stm.w r5,{r2,sb,lr}` @0x2251C2) — inferred:
   это ATAG/boot-params запись «физический адрес» (0x10200000 = регион SRAM/SLAVE-конфиг), а не запись в регистр.
3. **RPMB set_boot_info**: строк/символов `set_boot_info`/`boot_info` в preloader НЕТ (поиск proven).
   re-lk-seccfg.md описывает set_boot_info (block+8=boot_mode) на стороне **LK**. ⇒ preloader не
   пишет boot_mode в RPMB boot-info; единственный RPMB-контент preloader — rpmb_en/keyprovision
   флаги oplusreserve1 (см. re-preloader-daa-lk.md §3).
4. Прочие MTK-места записи boot-mode (регистры 0x10001xxx/IOC/рут-флаги) — targeted-sweep по
   константам 0x10007000/0x10007024/0x10200000/0x11003000 дал только перечисленное. Вывод:
   **канал передачи boot-mode preloader→LK в этой прошивке — программный (boot-tags/ATAG), а не HW-регистр** (proven-по-отсутствию записи, medium confidence).

---

## 4. Вывод: почему NORMAL, и можно ли из preloader-VCOM заставить fastboot

### Факт-цепочка (proven)
1. FASTBOOT-токен принят → `*0x2F4264 = 0x63`, ответ TOOBTSAF (@0x228F6E).
2. main boot-to-LK путь (0x232EDC): `*0x2F4264 != 0` → пропуск цикла ожидания battery/USB (0x232F30).
3. Перед прыжком: 0x23238C → **builder 0x231694** копирует `*0x2F4264` в boot-tag структуру (+0x28),
   строит таг «pl-boottag» (+ ассерт-валидация 0x232908), логает `boot to LK by ATAG reason=%d addr=0x%x`.
4. **Ни 0x10007024, ни RPMB boot-info preloader не трогает** (нет записей — proven absence).

### Почему телефон грузится в NORMAL (вывод)
0x63 **доходит до LK** — но как значение поля boot-tag-структуры, а не в том месте/виде, которое LK
использует для выбора fastboot. Подтверждается тем, что единственный наблюдаемый эффект 0x63 в
preloader — пропуск battery-wait. LK на этом устройстве (см. re-lk-rescue-surfaces.md §3) принимает
boot-mode из своего ATAG-канала **[0x50112024] / HW-регистр 0x10007024-nibble** — а preloader в
0x10007024 не пишет и, судя по составу тагов, FASTBOOT (0x63) кладёт в поле, которое LK-парсер
либо не мапит на fastboot, либо перезаписывает собственным определением режима (LK сам решает
fastboot по своему `oplus_usb_handshake`/кнопкам/`brom_meta_mode`-наследству — inferred).
Дополнительно: если устройством управлял mtkclient через BROM-режим (VCOM до preloader), LK вообще
может не получить 0x63, потому что путь BROM→DA не проходит через диспетчер preloader.

**Главный ответ: «почему normal» — 0x2F4264 консьюмерится только (a) как флаг skip-wait и (b) как
поле boot-tag; прямой записи в HW boot-регистр или в consuming-LK-поле нет, поэтому stock LK
остаётся в normal boot.** Это не баг трассировки — так устроен данный preloader: «fastboot» из
preloader-VCOM сессии он форвардить не умеет.

### Q4: что можно сделать из preloader-VCOM (практика)
- **AT-токен FASTBOOT сам по себе НЕ переводит в LK-fastboot** (доказано выше) — только пропускает
  ожидание батареи и попадает в boot-tag, который LK-ветка fastboot не потребляет.
- **brom_meta_mode=1/0x64** (аппаратный META до preloader — BOOT0/ключевые комбинации или BROM-флаги)
  → `0x2F4264=1` → boot-tag META → LK boot в META, не fastboot. Не даёт fastboot.
- Реалистичные пути форсировать fastboot **до DA**:
  1. **vol-key путь preloader**: в preloader есть `enter_preloader_by_vol_up_down` (строки/ветки в
     main, см. re-oplus-preloader-handshake.md) — на некоторых сборках он ставит boot mode 6/«download»
     в те же слоты; проверить на живом устройстве, влияет ли он на LK (untested).
  2. **patch-подход**: чтобы LK вошёл в fastboot, нужно менять либо LK (невозможно — cert2/RSA,
     re-preloader-daa-lk.md Q2), либо писать HW-регистр 0x10007024 из **DA2-сессии** (после DAA,
     с DA_BR-агентом): девайс после загрузки DA позволяет записать RGU-регистр и ребутнуться в
     режим, который LK прочтёт из nibble. Это тот же класс эксплойта, что LK boot-mode nibble
     (re-lk-rescue-surfaces.md §3) — требует рабочего DA2, что уже есть в mtkclient-пути.
  3. Подменить содержимое boot-tag preloader на лету (MITM preloader→LK): не реализуемо без
     патчинга preloader, который сам верифицируется (загрузка preloader подписана).

**Итог: из чистой preloader-VCOM сессии заставить stock LK войти в fastboot нельзя; нужно либо DA2-этап,
либо физические ключи (vol), либо менять LK (нереализуемо из-за подписи).**

---

## Evidence index

- VA=offset+0x200F10 — proven (re-preloader-daa-lk.md).
- Все xrefs слотов 0x2F4260/0x2F4264/0x2F4240/0x2F4244/0x2F4248 — proven (linear-sweep capstone,
  резолв pc-relative LDR; сохранён в /tmp/opencode/pre/xrefs.pkl).
- builder 0x231694: `+0x28 ← *0x2F4264` — proven (дизасм 0x2316D2–0x2316D4, литерал 0x231E38).
- Пул builder'а 0x231E30–0x231E48 (все 5 слотов + строка log_port + 0x2F3160) — proven (bytes).
- main-гейт 0x2F4240 = 1/2 (0x228852–0x228862) — proven.
- boot to LK by ATAG reason/addr строка 0x24F780, пул 0x232408 — proven.
- pl-boottag / pl_boottag_res assert — proven (строки 0x24FB18/0x24FB26, литерал-пул 0x232E68).
- Отсутствие записи в 0x10007024 / RPMB boot-info в preloader — proven-by-absence (sweep).
- Семантика «skip handshake» brom_meta_mode 1/0x64 → записи 0x2F4264=1 — inferred (сайт 0x64 не найден).
- Точная раскладка остальных слотов по полям структуры (0x2F4260/0x2F4240/0x2F4244/0x2F4248) — inferred.
- Причина, по которой LK не потребляет +0x28-поле как fastboot — inferred (высокая уверенность на
  базе живого наблюдения NORMAL + отсутствия альтернативных каналов).
