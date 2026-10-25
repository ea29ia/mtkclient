# HANDOFF → PC-агенту: DA1 HeapBait chain (RMX3630 / MT6789)

Дата: 2026-10-25. Ветка: `oplus-mt6789-unlock`. Предыдущий бриф:
`docs/notes/uswi.handoff` (его §4.1–§4.4 закрыты, см. ниже).

**Статус: офлайн-цепочка собрана и проверена в эмуляторе (PASS). На железе
не запускалась — USB-BROM/preloader в этой машине недоступен (adb только по
TCP: RMX3630, `14.0.0.420(EX01)`, mt6789).**

---

## 0. TL;DR

* Полная цепочка работает офлайн:
  `fail BOOT-TO (staging @0x40000000)` → `HeapBait fire (cb=0x40000000)`
  → `blx r4` → `стаб @0x40000000` → `sha256(patched DA2)` в `0x2688CC`
  → DA1 жив → `BOOT-TO` с патченным DA2 **проходит** проверку хэша.
* В payload **нет ни одного адреса кучи**: `{0xDEADBEEF, 0x2DF79C,
  0x40000000}` — константы. Блокер «D неизвестен на устройстве» снят.
* Уязвимая геометрия после прелюдии: `L=0x3C` (единственный exact-fit).
* Осталось: (1) хост-интеграция в mtkclient, (2) прогон на 200EX01 по USB,
  (3) перерезолв констант под DA1 сборки 420EX01.
* **2710EX01 не трогать** (DA1 закрыт, BROM efuse-locked).

---

## 1. Артефакты

| файл | что | запуск |
|---|---|---|
| `docs/notes/da1_emu.py` | базовый Unicorn-харнесс DA1 (не менялся) | `python docs/notes/da1_emu.py <da1.bin>` |
| `docs/notes/da1_heap_sweep.py` | свип declared length L, классификация соседа, fire-детект | `--lo --hi --step --json` |
| `docs/notes/da1_fixed_stage.py` | **актуальная цепочка** (staging + fire + stub + hash) | `python docs/notes/da1_fixed_stage.py` |
| `docs/notes/da1_fire_chain.py` | первая версия (стаб в куче, D предсказывается реплеем malloc) — только регресс/история | `python docs/notes/da1_fire_chain.py` |
| `docs/notes/reverse/re-da1-hash-patch-audit.md` | аудит DA1: 12 команд, hash-slot, BOOT-TO, free-list блокер | — |
| `docs/notes/da1_sweep_results.json` | 532 КБ сырых прогонов, **не коммитится** (генерится свипом) | — |

Окружение: Python + `pip install unicorn capstone` (проверено на unicorn
2.1.4). Образ: `docs/notes/rmx3630-da2/da1_allinone.bin` (200EX01).

Полный прогон `da1_fixed_stage.py` — ~7 секунд, эмулятор, без устройства.

---

## 2. Цепочка по шагам (все адреса — DA1 200EX01, база VA `0x200000`)

### 2.1 Boot/harness

* `heap_init` `0x2044C8`; registrar `0x200ED0` **обязателен** (иначе все
  команды `ERR!UNSUPPORTED`);
* `packet_len` global `0x2DE3F8 = 0x2000`;
* cmd_loop ходит в реальные USB-точки `0x24FC60`/`0x24FB80`; харнесс
  подменяет их на трамплины (`emu.rx`/`emu.tx`);
* session struct `0x2B0100`: `[0]=recv, [4]=send`.

### 2.2 Prelude: staging по фиксированному адресу

`CMD:BOOT-TO` (`0x201080`) **сначала** качает файл на `0x40000000`
(`bl 0x2500D8` @`0x2011E4`), и только потом считает SHA-256
(`bl 0x2522C4` @`0x201254`) и сравнивает с `0x2688CC` (`0x20128C`).

Поэтому отправляем blob с заведомо неверным хэшем:

* blob = `stub @+0` + нули + `sha256(patched DA2) @+0x80`, всего 160 байт;
* handler возвращает `0xC0070004` (hash mismatch, **не** транспортный
  `0xC0010001`);
* 160/160 байт остаются по адресу `0x40000000` — проверено чтением памяти
  после handler'а.

### 2.3 Fire

`CMD:DEBUG:DRAM-REPAIR` (`0x202C7C`), declared length `L=0x3C`:

* DA делает `malloc(L+4)` → чанк `0x4C`, capacity `0x40`;
* после прелюдии единственная дыра точного размера — узел `0x4C`
  (`D=0x2E9198`), следующий чанк `0x2E91D8` — живой XML-узел;
* host отправляет `L+0x10 = 0x4C` байт: нули + 12-байтовый fake-header
  `{0xDEADBEEF, 0x2DF79C, 0x40000000}` по смещению `0x40`;
* `recv` не клампится к остатку → `r7 > sb`, точного выхода нет → timeout
  → error path; `mxmlDelete` освобождает XML-узел-жертву;
* `free()`: `node = [victim_user-8] = 0x2DF79C`, `size = 0x40000000`,
  `str r1,[r0,#8]` @`0x2043CC` → **`dpc->cb = 0x40000000`**.

`L=0x3C` — единственный exact-fit после прелюдии; при `L≥0x40` fake-header
попадает в свободный remainder и ломает free-list (DA падает на следующем
malloc/insert).

### 2.4 Dispatch и стаб

`cmd_loop` `0x203C08`, `blx r4` @`0x2040D4` → `0x40000000`.

Стаб 76 байт (абсолютный, не PIC, но привязан к константам):

```
movw r2,#0xf79c ; movt r2,#0x2d      ; forged node 0x2df79c
ldr  r0,[r2]    ; ldr r1,[r2,#4]     ; prev / next
str  r1,[r0,#4] ; str r0,[r1]        ; unlink forged node
movw r3,#0x80   ; movt r3,#0x4000    ; digest @0x40000080
ldm  r3,{r0-r7}                      ; 32 bytes
movw ip,#0x88cc ; movt ip,#0x26      ; slot 0x2688cc
stm  ip!,{r0-r7}
mov  r0,#0
movw r1,#0xf7a0 ; movt r1,#0x2d      ; dpc struct
str  r0,[r1]    ; str r0,[r1,#4]     ; str r0,[r1,#8]
bx   lr                              ; -> 0x2040D8 (cmd_loop)
```

Важно: `ldm r3!,{r0-r7}` (writeback с базой в списке) — невалидная/
непредсказуемая инструкция, Unicorn её отвергает; используется форма без
writeback.

### 2.5 Проверка хэша

* `sha256(DA2 body, 0x56EC8)` = слот `0x2688CC`;
  * unpatched `2fd24335…7b75` (совпадает с образом);
  * patched (byte `0x54444 ^= 1`, внутри нулевого паддинга)
    `ab624266…d0b9`;
* настоящий `CMD:BOOT-TO` с патченным DA2: compare loop
  `0x20128C..0x2012B4` (32 байта), mismatch-ветка `0x201338` не взята,
  `rc=0`, `cb=0x40000000`, `arg=0x2DE180`.

---

## 3. Доказательства (что именно проверено)

`da1_fixed_stage.py` печатает 18 проверок, все PASS:

```
prelude_staged / prelude_hash_mismatch / prelude_not_transport
payload_from_constants / stub_not_in_download_buffer
exact_fit / victim_allocated / fire / blx_target
stub_entered / stub_returned
freelist / alloc / cmdloop / slot / sha_routine / bootto_gate
no_heap_address
```

Плюс «живучесть» после цепочки (исполнением, не осмотром):

1. обход free-list от `[0x2DF7DC]` через `+4` до sentinel — 2 узла,
   forged `0x2DF79C` отсутствует;
2. `malloc(0x100)` + `free` x3 — ok;
3. следующая команда `CMD:SET-HOST-INFO` — `rc=0`, `<result>OK</result>`;
4. `mem[0x2688CC:0x2688EC] == sha256(patched)` — ok;
5. BOOT-TO gate — `rc=0`, mismatch=False, 32 байта сравнены.

Геометрия после прелюдии (свип, шаг 0x4):

| L | D | chunk | exact fit | victim | free после overflow | cb |
|---|---|---|---|---|---|---|
| `0x10..0x38` | `0x2E9198` | `0x4C` | нет (нужно меньше) | — | нет | 0 |
| **`0x3C`** | `0x2E9198` | `0x4C` | **да** | `0x2E91D8` (user `0x2E91E4`) | **да** | **`0x40000000`** |
| `0x40..0x200` | `0x2EA088` | `0xDF84` | нет | — | нет | 0 |

Отрицательные контроли (не fake-PASS): `--no-sweep` даёт PASS с явной
пометкой «не проверено шагом 3»; диапазон без кандидата → `EXIT=1` и
`RESULT: FAIL`.

---

## 4. Что НЕ доказано / риски

1. **SHA-256 — аппаратный блок.** `0x2522C4` дёргает clock gate
   `0x1000108C` и движок `0x10210A08`, в образе нет software K-таблицы.
   В эмуляторе он смоделирован `hashlib`; нативно в Unicorn путь не
   проходит (probe: pc=`0x2536AC`, digest нет). Всё остальное (download,
   compare loop, обе ветки, аллокатор, диспетчер, стаб) — нативный код DA1.
2. **Build lock-in.** `0x201080`, `0x2688CC`, `0x2DF79C`, `0x2DF7A0`,
   `0x40000000` — это DA1 200EX01. На телефоне сейчас **420EX01**; нужен
   перерезолв (см. §5.2).
3. **Геометрия кучи на железе.** `L=0x3C` должен попасть в exact-fit узел
   `0x4C`, верхний сосед которого — живой XML-узел. В эмуляторе это
   детерминировано для истории «свежий DA1 → один fail BOOT-TO →
   DRAM-REPAIR(0x3C)». На устройстве прелюдия (команды mtkclient) другая:
   неверный L портит free-list и убивает DA-сессию (лечится перезаливом
   DA1, не кирпич). Слепой скан L — только с перезагрузкой между попытками.
4. **USB-реализм.** Пакетирование, таймауты и крипто-движок смоделированы;
   12-байтовое переполнение доставляется реальным recv без клэмпа —
   это и есть проверяемое поведение.
5. `0x40000000` исполняем на DA1 по смыслу BOOT-TO (DA1 прыгает туда), но
   на железе не подтверждено.

---

## 5. Следующие шаги (по порядку)

### 5.1 Хост-интеграция в mtkclient

Модуль `mtkclient/Library/Exploit/da1_heapbait.py`:

* `stage(da1, usb)`: отправить `CMD:BOOT-TO` с 160-байтовым blob (stub +
  digest), дождаться `0xC0070004` **до** hash-mismatch (не транспорт);
* `fire(da1, usb, L=0x3C)`: `CMD:DEBUG:DRAM-REPAIR` + overflow-payload
  (константы), затем 0x40-байтовый ACK (в нём digest, если понадобится
  вариант без staging);
* `verify(da1, usb)`: `CMD:BOOT-TO` с патченным DA2 → `rc=0`.
* раннер `docs/notes/da1_chain_run.py` (CLI, сухой прогон/--execute).

### 5.2 Авторезолвер констант DA1

Скрипт, который для любого DA1-блоба находит: `heap_init`, `dpc`/`head`,
hash-slot, registrar/таблицу команд, `cmd_loop`, `free`/`insert`,
`DRAM-REPAIR`, предикат #414 (команда есть, трипваера нет). Нужен для
420EX01 и C.25.

### 5.3 Прогон на железе

1. 200EX01 (разблокирован, безопасно): preloader → DA1 → stage → fire →
   verify; при падении — перезалив DA1, следующая попытка.
2. Только после успеха — 420EX01 (сначала резолв констант §5.2).
3. 2710EX01 — запрещено.

### 5.4 После DA2

Путь до RPMB-зеркала/разлока — в `docs/notes/uswi.handoff` §1 и
`docs/notes/reverse/re-heapbait-stabilize.md`; перед записью RPMB снять
блок `0x1DC..0x1DF` (0x400 B) и держать путь восстановления.

---

## 6. Воспроизведение

```bash
pip install unicorn capstone
cd ~/mtkclient

# актуальная цепочка (PASS ~7 s)
python docs/notes/da1_fixed_stage.py \
  --image docs/notes/rmx3630-da2/da1_allinone.bin

# регресс: первый вариант chain
python docs/notes/da1_fire_chain.py \
  --image docs/notes/rmx3630-da2/da1_allinone.bin

# свип геометрии
python docs/notes/da1_heap_sweep.py \
  --image docs/notes/rmx3630-da2/da1_allinone.bin \
  --lo 0x3c --hi 0x3c --step 0x4 --json /tmp/da1_sweep.json

# базовый харнесс
python docs/notes/da1_emu.py docs/notes/rmx3630-da2/da1_allinone.bin
```

---

## 7. Ключевые адреса (DA1 200EX01)

| параметр | значение |
|---|---|
| база образа | `0x200000` |
| heap base / size | `0x2E8000` / `0x10000` |
| heap head | `0x2DF7D0` (+0 base, +4 size, +8 sentinel, +0xC chain) |
| dpc struct / node | `0x2DF7A0` / `0x2DF79C` |
| `free` core write | `0x2043CC` (`str r1,[r0,#8]`) |
| `insert` | `0x2043D8` |
| `malloc` core | `0x2041E8` |
| `heap_init` | `0x2044C8` |
| `cmd_loop` / `blx r4` | `0x203C08` / `0x2040D4` |
| registrar | `0x200ED0` |
| `DRAM-REPAIR` | `0x202C7C` |
| `BOOT-TO` | `0x201080` |
| SHA-256 entry | `0x2522C4` (hardware engine) |
| DA2 digest slot | `0x2688CC` (32 B, file `0x688CC`) |
| staging / stub entry | `0x40000000` |
| digest в blob | `0x40000080` |
| download buffer (L=0x3C) | `0x2E9198` (только диагностика) |

---

## 8. Безопасность

* 2710EX01 — не запускать DA1-эксперименты: DA1 закрыт, BROM efuse-locked.
* 200EX01 — тестбокс: падение DA1 лечится повторным входом в preloader.
* Не писать в `seccfg` через `WRITE-FLASH` (анти-тампер затирает).
* RPMB: перед записью снять блок `0x1DC..0x1DF`, счётчик записи необратим.

---

## 9. Состояние репозитория

* ветка `oplus-mt6789-unlock`; бриф написан поверх `0ca8b55`, сам бриф
  входит в коммит `1266b18`;
* в коммите с этим брифом: три харнесса, аудит-нота, этот файл;
  `da1_sweep_results.json` в `.gitignore` (генерируемый артефакт);
* `docs/notes/uswi.handoff` остаётся историческим брифом (§4.1–§4.4
  закрыты этим файлом).
