# Campaign log — RMX3630 (MT6789) unlock / ADB campaign

> Snapshot of the working log kept at `/home/musin/problem_status.md` (Russian, append-only).
> Committed to the fork on 2026-10-24 so the whole trail lives with the code.
> §11 is superseded by §12–§13; the current conclusions are in
> `docs/notes/reverse/re-unlock-campaign-2026-10-24.md` and
> `docs/notes/reverse/re-consistency-audit-2.md`.

# RMX3630 (MT6789/Helio G99) — разблокировка загрузчика. Статус проблемы.

Дата: 2026-10-24. Рабочая копия: `/home/musin/mtkclient` (форк ea29ia/mtkclient,
ветка oplus-mt6789-unlock). Все коммиты сделаны. Бэкапы целы.

---

## 1. Цель кампании

Разлочить bootloader на realme RMX3630 (экран мёртв, только USB/BROM/DA путь),
чтобы дальше получить ADB/scrcpy и root. Кнопочные комбинации в fastboot не
попали ни разу; DA reboot-to-fastboot, Plan E (AT-токен) и RGU-nibble-3
провалились (nibble 3 → LK boot-loop). Выбран Plan B: forge seccfg с
lock_state=3 + валидный HACC-хэш (device-bound), RPMB-зеркало не нужно
(см. §3).

## 2. Что установлено твёрдо (proven)

- **seccfg-статусы (LK реверс, `re-lk-seccfg.md`)**: 1=LKS_DEFAULT(locked),
  2=LKS_MP_DEFAULT(locked), 3=LKS_UNLOCK, 4=LKS_LOCK. Unlock-запись LK пишет
  только «3». Текущее состояние флеша: **lock=2 (LOCKED), девайс жив и
  загрузится** — кирпича нет.
- **Формат записи V4**: `MMMM, ver=4, size=0x3C, lock, dm_verity, sboot,
  0x45454545` + 0x20-байтный digest на offset 0x1C. Digest = HACC-AES-ECB
  (fixed seeds) от SHA256(первые 0x1C байт). Зависит ТОЛЬКО от 0x1C-заголовка.
- **Наш стек воспроизводит LK-хэш**: `SecCfgV4.parse()` свежепрочитанной
  LK-записи вернул `hwtype=V4` (V3-legacy SEJ) → `SecCfgV4.create("unlock")`
  даёт LK-валидный payload lock=3 (пейлоад сохранён:
  `/tmp/seccfg_unlock_payload.bin`, 512 B).
- **RPMB не нужен** (разведка recon2, read-only): RPMB-ключ на юните
  **НЕ программирован** (GET-RPMB-KEY-STATUS = raw `NOT-EXIST`; вердикт в
  скрипте имел substring-баг «EXIST in NOT-EXIST» — реальный ответ NOT-EXIST).
  RPMB сектора 0..127 — все нули, и это ПОДЛИННЫЕ данные (EXP2: чтение с
  заведомо неверным ключом прошло без ошибки → чтения не гейтятся ключом).
  Следствие: LK-зеркало никогда не писалось → ветка [DC-3]
  `double_check_lock_state` (mirror+0xC == 0 ≠ 1) — «no action» → forged
  seccfg lock=3 ПЕРЕЖИВЁТ загрузку без всяких RPMB-операций.
- **devinfo в GPT отсутствует** (есть seccfg, frp, misc) — lock живёт только
  в seccfg.
- **Рантайм-патчи DA2** (все в `xml_lib.py: apply_oplus_runtime_patches`,
  применяются при коннекте, видны в логе «Runtime-patched ...»):
  digest-accept 0x40034f94, write-deny NOPs 0x400021a0/0x400031a4/0x400031b0,
  rwreg-гейты, CUSTOMREGW/CUSTOMMEMR-примитивы, erase-kill (OPLUS_PATCH_ERASE_KILL:
  0x4000325c MOV r0,#0 + 0x40002214 NOP), HACC-hang NOPs
  (OPLUS_PATCH_HACC_HANG: 0x40039848/0x400397e0/0x40034b18 NOP + ACC-skip
  0x4000c210), а также запрещённые к использованию state-writers
  0x40035000/14 (SLOT IDENTITY — выключены навсегда).
- **Write-ops таблица DA**: `0x40054330`, program-op = `0x400313c0` (обёртка
  над `0x40029758`), erase-op = `0x400313e8`, INIT выбирается битом 6 байта
  `0x11200001` (живой = 1 → program-указатель установлен). Дамп из живой
  сессии подтверждает: указатели валидны, бит=1. Гипотеза «программный
  указатель не инициализирован» опровергнута.

## 3. Хронология инцидента (как возникла проблема)

1. Разведка (recon, recon2) — только чтения: seccfg live lock=4, RPMB нули,
   ключ не программирован. Все чтения работали, включая 8 MB и 32 KB сканы.
2. **Боевой прогон unlock** (`PLAN_B_GO=1 ./run_planb.sh`): бэкап снялся
   (md5 12a94a3f... — совпал с оригиналом), payload lock=3 построен,
   WRITE-PARTITION: upload 8 MB дошёл до 100% (36 MB/s) → сессия умерла
   (EIO «Wrong length (0)»), верификация не прошла. Процесс python молча умер.
3. Проверка свежей сессией: флеш **не нулевой** — валидный V4 с **lock=2**
   (не наш 3, не оригинальный 4).
4. **Прогон restore** (`PLAN_B_GO=1 ./run_planb_restore.sh`, с новыми патчами
   ERASE_KILL+HACC_HANG): перед записью флеш снова читался как валидный
   lock=2; WRITE-PARTITION: upload 8 MB 100% (30 MB/s) → сессия снова молча
   умерла после upload.
5. Полная проверка 8 MB (`check_seccfg`): md5 `5a17c8d5...` ≠ ни бэкап, ни
   payload; голова — LK-запись lock=2; хвост [0x1000:] — все нули.
6. С того момента **все сессии не могут читать seccfg**: get_gpt проходит,
   а первый же READ-FLASH seccfg виснет (baseline, +HANG) или падает
   «Wrong length (0)»/«Error on downloading data:OK@0x200» (+KILL).
   Чтения других регионов (GPT, RPMB, RAM) работают; программа-тест
   smallwrite 0x200 так и не дошёл до записи (умер на первом чтении).
7. Device сидит в preloader VCOM между сессиями (22d9:0006), ЛК-загрузок
   с момента краша не было.

## 4. Что делаем сейчас

**Немедленный шаг — полный power-cycle девайса** (жёсткий ресет питания
15–20 с, затем обычный вход в VCOM: Vol+ и Vol− → USB). Единственное, что
реально ресетит UFS-девайс целиком.

После возвращения чтений:
1. `./run_read_test.sh` — контроль, что 4 чтения seccfg проходят;
2. `SMALL_GO=1 ./run_smallwrite.sh` — тестовая запись 0x200 байт оригинала
   в начало seccfg (ноль риска) + same-session readback;
3. Если коммитится — forge-запись lock=3 (первые 0x78 байт seccfg, весь
   контент) через WRITE-FLASH offset=0x0 одним куском 0x200;
4. Верификация readback lock=3 → ребут → Orange State (bootloader unlocked).

## 5. Теории (по убыванию вероятности)

### Т1. Заклинившая UFS-очередь после краша DA посреди program-фазы
Крах DA во время 8 MB program-фазы оставил UFS-команду записи висеть.
WDT warm-reset поднимает SoC и preloader заново, но UFS-контроллер целиком
не ресетится — регионы, затронутые записью, hang'ают любой доступ.
Подтверждения: чтения работали до краха (даже 8 MB), и не работают после
(любой длины, любыми патчами); падает именно доступ к seccfg-региону.
Лечение: полный power-cycle (reset UFS). Это основная рабочая теория.

### Т2. DA крашится на program-фазе всегда (размер-независимо)
Оба 8 MB прогона умирали после upload 100%; first-read-fail — отдельный
симптом той же поломки (см. Т1). Если после power-cycle записи все равно
умирают — искать краш-сайт в program-движке (0x400313c0 → 0x40029758,
0x400286ac/0x40028884/0x400288e4, post-write pass 0x4002c4a0, flush 0x40008234
= bx lr пустышка). Кандидат-патч: NOP post-write pass / flush в WRITE-FLASH
обработчике (0x4002b0x → 0x4002c4a0, адреса из re-writeflash-scrubber.md §5).

### Т3. Размер-зависимый крах (bounce-буфер/heapbait packet_length)
heapbait выставил DA packet_length = 2097152 (2 MB). Для WRITE-PARTITION
8 MB могли не влезть в bounce-буфер DA → heap corruption → крах. Малая
запись 0x200 тогда пройдёт без проблем. Это согласуется с планом (пишем
0x200, не 8 MB).

### Т4. lock=2-«регенерация»
После смерти первой записи LK (или DA) пересобрал seccfg: LK увидел нулевой
seccfg → init-NV writer записал дефолт lock=1 → RPMB-read-fail → force re-lock
→ lock=2. Содержимое на флеше — именно LK-продукт (хвост нулевой, размер
0x3C-записи, lock=2 = MP_DEFAULT). Это не враг: девайс консистентно LOCKED,
а наша forge-запись полностью заменит главную запись (LK сверяет хэш каждой
записи независимо; main-записью будет наша).

### Т5 (маловероятная). Read-путь seccfg в DA фейлит сам по себе
READ-FLASH seccfg идёт через валидирующий/нормализующий слой (digest
проверка 0x40034f94→accept-патч стоит). Но GPT/другие регионы читаются,
а до патчей те же чтения работали — значит дело в состоянии девайса (Т1),
не в коде чтения.

## 6. Железные правила (напоминание)

- WRITE-FLASH на seccfg — ЗАПРЕЩЁН навсегда (исключение: текущий smallwrite
  тест — WRITE-FLASH с явным offset, малый объём, байты оригинала; после
  возврата чтений — заменить forge-запись на WRITE-FLASH offset=0x0 0x200 Б
  только с подтверждением юзера).
- State-writer патчи 0x40035000/14 — не включать.
- OPLUS_SBC_PATCH=0 всегда.
- Бэкапы: `/home/musin/seccfg_backup.bin` (md5 12a94a3ffbfc1a7f344e1dd6837b359a,
  оригинал lock=4), полный бэкап разделов
  `/home/musin/rmx3630_backup_20261024_095607/`.
- Сессия: `OPLUS_PATCH_LEVEL=5 OPLUS_SKIP_SLA=0 OPLUS_SKIP_HWINFO=1
  OPLUS_NO_DRAIN=1 OPLUS_LEGACY_HOST=1 OPLUS_STORAGE=ufs
  OPLUS_HWINFO_LATE=1 OPLUS_WRITE_BYPASS=1 OPLUS_FLUSH=1` (в run_*.sh).
- Останов после 2 одинаковых неудач; все железные шаги — только по
  подтверждению юзера.

## 7. Файлы

- `/home/musin/run_read_test.sh` — изоляция чтений (HANG=1/KILL=1 — флаги).
- `/home/musin/run_smallwrite.sh` — тест 0x200-записи (SMALL_GO=1).
- `/home/musin/run_check_seccfg.sh` — full 8 MB read + md5-сверка.
- `/home/musin/run_probe_writepath.sh` — дамп таблиц DA + digest-сверка.
- `/home/musin/run_planb.sh` — боевой unlock (после починки записи).
- `/home/musin/mtkclient/docs/notes/planb_execute.py`, `planb_restore.py`.
- `/tmp/seccfg_unlock_payload.bin` — forge lock=3 (512 B, валидный V4).

## 8. РАЗГАДКА (2026-10-24, вечер): размер блока UFS = 0x1000, НЕ 0x200

Лог каждой сессии печатает: "Storage pre-seeded from OPLUS_STORAGE=ufs
(block 0x1000...)". Сверка хронологии:
- ВСЕ успешные чтения были кратны 0x1000: 8 MB, 0x1000, 32 KB RPMB;
- ВСЕ падения стартовали с транфера 0x200 (smallwrite упал на ПЕРВОМ
  чтении 0x200 ещё до записи; read_test — тоже);
- DA подтверждает length-ack "OK@0x200" (число он видит), но data-фаза
  виснет/умирает на нестыковке длины с блоковым слоем UFS (4096).
"Деградация" была артефактом: мы всегда тыкали 0x200.

Фиксы: все чтения 0x1000-aligned (read_test), smallwrite-чанк 0x1000,
unlock-пейлоад паддится до 0x1000 (planb_execute). WRITE-PARTITION шлёт
pre_erase=NO (штатный skip-erase). HACC-free патчи читателя
(ANTICLONE+HACC_READ) остаются — они снимают зависание HACC-валидации.

## 9. Эксперимент para (2026-10-24 вечер): program-фаза НЕ КОММИТИТ ВООБЩЕ

Дискриминация завершена: WRITE-PARTITION паттерна в НЕзащищённый раздел para
(pre_erase=NO, fullsize, block-aligned, upload 100% → чистый CMD:END,
rxleft=None, «Successfully wrote») → флеш para НЕ ИЗМЕНИЛСЯ.
=> Это не seccfg-защита: program-движок молча выбрасывает данные для ЛЮБОГО
раздела. Протокольный дедлок побеждён (см. §8 и коммиты 82935a3/cf8030f/
23b8262/95bcf47: fullsize-пад, raw=False, снят erase-gate NOP 0x40002214,
убран in-handshake readflash).

Обновлённый фокус: молчаливый skip program-фазы в DA:
- кандидаты: program dispatcher 0x4002aac0 (условия вызова program-op),
  engine-2 0x400306ac (пост-цикловая обработка), commit 0x40008234
  (bx lr — пустышка по реверсу), close/flush 0x4002f7bc,
  program core 0x40029758 (0x40028030 gate → ветки записи);
- наш ACC-skip патч 0x4000c210 beq→b — под подозрением (надо проверить,
  в какой он функции и не ломает ли WRITE-PARTITION program);
- live-проба уже опровергла «указатель не инициализирован»
  ([0x40054330+0x10]=0x400313c0, bit6@0x11200001=1).

Запущен фоновый реверс-агент: полный трейс WRITE-PARTITION → program до
реальной записи в UFS + конкретный фикс. Отчёт будет:
docs/notes/reverse/re-writepartition-silent-skip.md

Бэкапы не тронуты: seccfg = оригинал (lock=4, md5 12a94a3f...), para
восстановлен после теста (rb2 == orig).

## 10. КОРНЕВАЯ ПРИЧИНА silent-skip найдена и устранена (2026-10-24)

- Патч `xml_lib.py`, подписанный «oplus image hash-list check 0x4002f804»,
  на деле ставил stub `mov r0,#0; bx lr` в **диспетчер записи consumer'а**
  0x4002F804 (policy → hash-гейт r8 → is_sparse → bulk-init 0x4002D5A8 →
  write-loop 0x4002D66C). Каждый чанк «успешно» обрабатывался без записи.
- Диагностика: F5-маркер (0x4006E7C8) оставался 0, bulk handle 0x4006E790
  нулевой, ctx2+0xE0/E4=0, `Download_data end.` есть, флеш чист.
- Фикс: stub вынесен за `OPLUS_PATCH_F804_STUB` (**OFF по умолчанию**),
  коммит `bcf4011`.
- Верификация (test7live): F5-маркер исполняется, handle инициализирован
  (+0x8=0x88000 LBA, +0x34=0x4006E6A0 region-list), `para` COMMITTED
  (`PARATEST...`), затем восстановлена нулями (`[+] para RESTORED`).
- ВАЖНО: F5-маркер как есть портит sparse-байт (в 0x4002F858 r1 = policy[+2],
  а не len) — использовать только как индикатор «диспетчер исполнялся»,
  в боевых прогонах не включать.
- Следующий шаг: `./run_planb.sh` — боевая запись seccfg (lock=3).

## 11. UNLOCK ВЫПОЛНЕН (2026-10-24 20:09) — УСТАРЕЛО, см. §12/§13

- `PLAN_B_GO=1 ./run_planb.sh` → WRITE-PARTITION seccfg (8 MB, pre_erase=NO).
- Readback в той же сессии: `magic=0x4d4d4d4d ver=4 size=0x3c lock_state=3
  dm_verity=0 sboot=0 end=0x45454545` → **WRITE COMMITTED**.
- Бэкап перед записью: `seccfg_before_unlock_20261024_200955.bin`
  (md5 12a94a3ffbfc1a7f344e1dd6837b359a — оригинал lock=4).
- Отправлен WDT-reboot. Ожидание: Orange State, затем normal-mode USB
  (22d9:2046) и ADB.

## 12. РЕЗУЛЬТАТ: запись работает, unlock НЕ ДЕРЖИТСЯ (2026-10-24, вечер)

Полный отчёт: `docs/notes/reverse/re-unlock-campaign-2026-10-24.md`

### Что подтверждено
- Путь записи жив (фикс 0x4002F804): `para` записана (`PARATEST…`) и
  восстановлена нулями; `seccfg` реально записан с `lock_state=3`, readback
  в той же сессии подтвердил (`test8final`).
- После ребута `seccfg` вернулся к ОРИГИНАЛУ байт-в-байт (8 МБ, md5
  `12a94a3ffbfc1a7f344e1dd6837b359a`, 0 различий) — `snap`.
- Устройство живое, грузится в Android, USB `22d9:2046` = только Audio/MIDI
  (2 интерфейса), ADB нет, MTP нет.

### Механизм откатa (inferred, код proven)
- LK `double_check_lock_state` 0x500556C4 ← вызов 0x500026B8: читает RPMB-зеркало
  через TEE op 0x1DC (0x400 B = сектора 0–3), `block+0xC == 1` → 
  `sec_cfg_set_lock_state(locked)` + power-off. HACC детерминирован, поэтому
  перезапись байт-идентична оригиналу — «откат» не означает «запись не прошла».
- Порядок загрузки LK: `boot_mode_check` (0x5000E15C) → `sec_boot_init`
  (0x5000E270) → DC.
- Fastboot недостижим из DA: LK входит в FASTBOOT только при HW-ниббле
  `0x10007024 & 0xF == 3` (гейт 0x5000ACA4–0x5000ACB8) или ATAG 1/7 —
  оба канала пишет preloader. `SET-BOOT-MODE=FASTBOOT` принимается, но
  устройство уходит в `0006 → 2046`.

### RPMB: данные DA недостоверны
- `planb_recon2`: чтение секторов 0..0x7F вернуло все нули, причём чтение
  УСПЕШНО и с заведомо НЕВЕРНЫМ ключом (0x11*32) → путь `CUSTOMRPMBR`
  (патч `mmc_rpmb_send_command`, eMMC-вариант) не доходит до реального UFS RPMB.
- `GET-RPMB-KEY-STATUS` вернул сырое `NOT-EXIST`, но старый скрипт печатал
  «EXIST» (подстрока в «NOT-EXIST») — исправлено.
- При этом LK зеркало читает и видит `locked=1` ⇒ ключ реально прошит;
  значит вердиктам DA по RPMB на этом UFS доверять нельзя.

### Открытый вопрос №1 (следующий шаг)
8 МБ образ обнулял вендорский маркер по смещению `0x200`
(`90 79 09 22 00 00 00 01`) — после ребута он снова на месте. DC переписывает
только 0x3C байт, значит либо **запись не дошла до хвоста**, либо есть
**внешний полный restore**. Разрешается тестом `write_reach_test.py`:
маркеры в начале и в последнем 0x1000 `para`, запись, чтение обоих концов,
затем восстановление оригинала с полной проверкой.

Запуск: `WRITE_REACH_GO=1 ./run_write_reach.sh` (по умолчанию dry-run).
Рядом: `./run_rpmb_probe.sh` — read-only перепроверка RPMB (ключ D vs неверный
ключ + корректный разбор key-status).

### Состояние на конец кампании
`seccfg` = оригинал (lock=4), устройство грузится, ADB/fastboot недоступны.

## 13. КОНСИСТЕНТНОСТЬ ДОКОВ: аудит #2 (2026-10-24, вечер)

Полный отчёт: `docs/notes/reverse/re-consistency-audit-2.md`.
Проверено 5 параллельными агентами + ручная перепроверка по бинарям/логам.

### Что было неверно и исправлено
1. **Зеркало RPMB — НЕ сектора 0–3.** `0x1DC` — это поле адреса в кадре RPMB
   (`frame+0x1F8`, 0x5002FE78-88; TEE-путь 0x5003E5C4). Значит зеркало LK
   лежит в блоках **0x1DC–0x1DF** (байты 0x1DC00–0x1DFFF). Все выводы
   «сектора 0..0x7F нулевые ⇒ mirror=0» были про чужой регион — вычеркнуты.
   Затронуты: `re-mtkclient-rpmb-audit`, `re-tee-efuse`, `re-tbase-sfsrp`,
   `re-lk-rpmb-lock`, отчёт кампании.
2. **ATAG ≠ fastboot.** ATAG 1 → режим 1 (META), 4 → factory, 7 → 7
   (баннер «UNKNOWN BOOT»); 0x63 из ATAG не получается. В FASTBOOT ведут
   ровно два пути: HW-ниббл 3 (0x5000ACA4) и `reset-reason class && lock==3`
   (0x5000ACBC→0x5000AD04, GPIO только логируется). Мой прежний «overcorrection»
   про GPIO снят; в `re-lk-bootmode-priority.md` все кодовые адреса вообще
   сдвинуты на +0x78 — нужна перегенерация.
3. **`misc` не нулевой:** в +0x800 лежит BCAB (`…42434142 01020000 ff007f00`),
   14 ненулевых байт; 6 байт (0x80C/0x80E/0x81C-0x81F) изменились за сессию —
   LK сам перезаписал BCAB (слот/чексумма).
4. **`pre_erase=NO` отправляется всегда** (xml_cmd.py:453) — фаза erase
   пропускалась флагом, а не «отсутствующим узлом». Модель «silent erase» в
   `re-write-chain`/`re-write-partition-offset`/`re-writeflash-scrubber` неверна;
   наш `OPLUS_PATCH_ERASE_KILL` — перестраховка.
5. **Длина программирования = принятая длина** (`len=[rec+0xC]+[rec+0x10]`,
   выход по `accumulated==target`), а не «вся партиция». 8-МБ запись seccfg
   была size-matched, поэтому вопрос «почему вернулся маркер 0x200» остаётся
   открытым (внешний restore или неполная запись).
6. **Ошибки в наших скриптах (критично):** `(b"REACHHEAD"*128)[:0x1000]` =
   1152 Б, `(b"PARATEST"*128)[:0x1000]` = 1024 Б → образ укорачивался, а
   сравнение с 0x1000 всегда False. Успешные ветки в `write_reach_test.py`,
   `f5_dump.py`, `para_write_test.py` были недостижимы (реальное доказательство
   записи — печатный hex `5041524154455354…`). Всё исправлено: маркеры ровно
   0x1000, `assert len(img)==full`, restore в `finally`, `para_restore_zero`
   больше не «восстанавливает» сам зонд.
7. **LK seccfg:** ветка «backup валиден ⇒ self-heal» хеширует **main**
   (0x50144840) и сравнивает с дайджестом **bak+0x1C** (0x5014489C) —
   повреждённый main туда не попадает, уходит в init-NV (lock=1);
   `sec_cfg_get_lock_state` при ошибке отдаёт **1**, а не 0.
8. **DA2:** 0x4002AAC0 — мёртвый код (слот таблицы +8, не +0x10);
   0x4000EA94 — рекурсивный free (mxmlDelete), не «send response»;
   `hash_binding` — бит 2, не 1; `g_oplus_auth_status` = 0x4005455C.
   Проверено, что `DA_BR.bin` = 0x68AB8-байтный заголовок + `da2_oplus.bin`
   (отличие только в 254 байтах подписи) — адреса доков
   применимы к рабочему DA (один агент ошибочно решил иначе).
9. **t-base:** магия суперблока — `K400RPMB` (0x424D5052_3030344B), а не
   `4400RPMB`; «S≥4» выведено из неверной геометрии зеркала и снято;
   «чтение RPMB не требует ключа» неверно (запрос без MAC, ответ с MAC).

### Что осталось верным
Путь записи (F804), HACC-дайджест seccfg, DC-ветка (mirror==1 → re-lock +
power-off), `set_boot_info_to_rpmb` (locked=(flag==0)), hash-mismatch ⇒
обнуление буфера ⇒ успех, отсутствие второй копии seccfg в снятых партициях,
MIDI-only USB, `expdb` = 0.

### Следующие шаги (обновлено)
1. `WRITE_REACH_GO=1 ./run_write_reach.sh` — теперь корректный тест (Q1).
2. `./run_rpmb_probe.sh` — читает **0x1DC–0x1DF**, сравнивает данные под
   ключом D и неверным ключом (read-only).
3. Эксперимент с reset-reason для пути (b) в fastboot.
