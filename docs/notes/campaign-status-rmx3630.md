# Campaign log — RMX3630 (MT6789) unlock / ADB campaign

> Snapshot of the working log kept at `/home/musin/problem_status.md` (Russian, append-only).
> Current summary: `docs/notes/STATUS-rmx3630-2026-10-24.md`.
> Handoff for the next agent: `docs/notes/HANDOFF-2026-10-25.md`.

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

## 14. test9 / test9a: оба вопроса закрыты (2026-10-24 21:40)

### write_reach (log `test9`)
`WRITE_REACH_GO=1 ./run_write_reach.sh`:
маркеры в начале И в конце (`0x7f000`) записались, образ 0x80000, restore
вернул md5 `00ff461906b45fc4af74f81839a30069`. ⇒ **DA пишет всю партицию**.
Значит 8-МБ seccfg дошла до конца, и вернувшийся маркер `0x200` — это
**внешний полный restore**, а не неполная запись.

### rpmb_probe (log `test9a`)
Блоки `0x1DC–0x1DF` вернули НАСТОЯЩИЕ данные:
`sboot=0 dev_info=1 bootmode=0 locked=1 aux=0`, строка `"RMX3630RU"` в +0x20,
SHA-256 валиден. Блоки 0–3 пустые. Чтение неверным ключом дало те же байты
(запрос RPMB-read без MAC — это ничего не доказывает про ключ).
`GET-RPMB-KEY-STATUS` = `NOT-EXIST` (на UFS слабый сигнал).

### Следующий шаг — `run_rpmb_unlock_mirror.sh`
`docs/notes/rpmb_unlock_mirror.py`: dry-run читает зеркало и строит unlocked
блок; `MIRROR_WRITE_GO=1` пишет его ключом D, проверяет readback, и только
если запись встала — пишет seccfg lock=3 и перезагружает. Если ключ не тот,
запись отвергается (JEDEC auth failure), seccfg не трогается.
Откат: `MIRROR_RESTORE=1` из `/home/musin/rpmb_mirror_before.bin`.

## 15. test11: RPMB-зеркало ЗАПИСАНО (2026-10-24 21:46)

`MIRROR_WRITE_GO=1 ./run_rpmb_unlock_mirror.sh`:
- ключ D (`75a41c1a…`, SEJ/HACC от MEID) **подошёл** — запись блоков
  `0x1DC–0x1DF` на UFS принята, readback: `locked=0`, `hash VALID`;
- затем в той же сессии записан `seccfg lock=3` (readback подтвердил),
  свежий бэкап `seccfg_before_mirror_unlock_20261024_214627.bin`
  (md5 `12a94a3f…` = сток);
- сохранены: `/home/musin/rpmb_mirror_before.bin` (md5 `2374972d…`, locked=1)
  и `/home/musin/rpmb_mirror_new.bin` (md5 `11a2d0c1…`, locked=0).

После ребута устройство **не вышло в Android**: в dmesg многократные
`22d9:0006` (preloader) с циклом ~110 с. Причина не установлена (ритуал
включения / цикл на preloader / побочка от записи RPMB).

Добавлен read-only чекер `docs/notes/unlock_state_check.py`
(`./run_unlock_state_check.sh`): читает `seccfg` (заголовок + полный md5) и
зеркало `0x1DC–0x1DF`, печатает вердикт:
`lock=3 + mirror locked=0` → unlock удержался.
Откат зеркала: `MIRROR_RESTORE=1 ./run_rpmb_unlock_mirror.sh`.

## 16. test12: unlock УДЕРЖАЛСЯ, Android не поднялся (2026-10-24 21:55)

`./run_unlock_state_check.sh`:
- `seccfg`: `lock=3 dm_verity=0 sboot=0`, полный md5 `a75ce366…` (не сток);
- `RPMB mirror`: `locked=0`, hash VALID, md5 `11a2d0c1…` — **ровно наш блок**,
  никто его не переписал;
- вердикт: **UNLOCK PERSISTED**.

Нюанс: вендорский маркер `seccfg+0x200` (`9079092200000001`) снова на месте,
хотя наш 8-МБ образ его обнулял, а заголовок остался наш. ⇒ есть отдельный
актор, который восстанавливает только область 0x200 (preloader или NV-init),
не трогая основную запись.

Android не появился как `22d9:2046`; в dmesg только `22d9:0006` (preloader)
с циклом ~110 с — так же выглядит **выключенный** телефон с
`off-mode-charge=1` (в `para` ENV есть `off-mode-charge=1`; ранний тест para
потерял `dm_ota=1` — безвредно). То есть «не поднялся» пока не доказано.

Диагностика: `/home/musin/watch_usb.sh` (пишет изменения USB 240 с) + реальное
включение кнопкой Power при подключённом кабеле. Если снова preloader —
откат в сток (`MIRROR_RESTORE=1` + `seccfg lock=4`) для восстановления
базовой загрузки, затем другой вариант unlock.

## 17. ИТОГ / ГДЕ МЫ (2026-10-24 22:05)

Сводка: `docs/notes/STATUS-rmx3630-2026-10-24.md`.

### Нарыли
- «Тихая запись» = наш же stub в диспетчере 0x4002F804 (снят, по умолчанию OFF).
- WRITE-PARTITION пишет **весь** регион (test9: маркеры в голове и хвосте + restore).
- `pre_erase=NO` отправляется всегда; erase пропускался флагом.
- Зеркало LK — в RPMB-блоках **0x1DC–0x1DF** (0x1DC = поле адреса JEDEC-кадра).
- Формат: +0x4 sbc, +0x8 bootmode, +0xC locked, +0x10 aux, +0x20 "RMX3630RU",
  +0x3E0 SHA-256.
- **SEJ/HACC-ключ `75a41c1a…` = реальный RPMB-ключ**: аутентифицированная
  запись на UFS принята.
- FASTBOOT: только HW-ниббл 3 или `rc_wdt-class && lock==3`; ATAG 1/4/7 — нет.
- В доках было ~40 ошибок → аудит #2 + errata во всех затронутых файлах.

### Смогли
`seccfg lock=3` + `RPMB mirror locked=0` **удержались после ребута** (test12),
зеркало = наш блок `11a2d0c1…`, seccfg full md5 `a75ce366…`. Это первый
устойчивый unlock на аппарате.

### Где мы
Телефон пока не предъявил `22d9:2046` (Android); в 22:00 после hard reset
(Vol+ + Power) на USB вообще ничего (test13 пуст). Гипотезы: (1) телефон
выключен/зарядка при `off-mode-charge=1`; (2) LK выключает (AVB/boot-state);
(3) t-base счётчик RPMB. Проверка — `watch_usb.sh` + Power; состояние —
`./run_unlock_state_check.sh`; откат — `MIRROR_RESTORE=1` + сток seccfg
`…214627.bin`.

## 18. Лог `ye`: restore-баг и preloader-цикл (2026-10-24 22:20)

- `MIRROR_RESTORE=1` сработал **вхолостую**: скрипт сохранил текущий
  (разлоченный) блок в `rpmb_mirror_before.bin`, затерев эталон, и «восстановил»
  его же. Исправлено: restore не пишет в before; источник проверяется
  (locked=1+hash) по списку; есть пересборка locked-блока из payload.
  Эталон: `/home/musin/rpmb_mirror_locked.bin` (`2374972d…`).
  На устройстве зеркало по-прежнему `locked=0`.
- dmesg: `0006` циклами 16 с и 39 с, `2046` нет ни разу. `hardreboot` —
  не существует (опечатка), Power, похоже, не нажимали.
- Добавлен read-only `boot_forensics.py` (`./run_boot_forensics.sh`):
  `oplusreserve1[0..0x40]` (LK читает 0x34 байта в 0x500053E0 и может уйти
  в RECOVERY), `misc` BCB/BCAB, `expdb`, `boot_para`, `seccfg`.

## 19. Форензика загрузки (2026-10-24 22:35)

- `oplusreserve1[0..0x34]` — дескриптор UFS (`YMTC`, `YMUS8B2TE2A2C1`, `7.3`,
  плюс 2 контрольных dword), НЕ boot-fail флаг. `0x500053E0` возвращает 0 на
  успехе (`mov w0,wzr` @0x50005564), отрицательные коды только при ошибке I/O;
  в `boot_mode_check` это `mode=2 (RECOVERY)` только при ошибке. Наш раздел
  читается ⇒ recovery ни при чём.
- `misc`: BCB пуст, BCAB валиден, 6 байт отличаются от бэкапа (LK писал блок);
  `expdb` = 0; `boot_para` = 0.
- Гипотеза «Orange State ждёт кнопку» — **опровергнута кодом** (фиксированный
  mdelay 5 с, опроса кнопок нет). Ведущая — H2 (сдвиг счётчика RPMB → t-base
  fatal → FBE). H3 (неестественная комбинация `lock=3` + `sboot=0`) — проверить
  вариантом с `sboot=1`.
- Инструмент: `rollback_stock_with_canary.py` (`./run_rollback_stock.sh`,
  запись только с `ROLLBACK_GO=1`): канарейка BCAB в `misc`, зеркало → locked=1,
  seccfg → сток, ребут. Канарейка отвечает на вопрос «запускался ли LK».

## 20. Канарейка: LK РАБОТАЕТ + дефект методики (2026-10-24 22:50)

- Откат выполнен и проверен: `misc` канарейка `XXXX` → после ребута снова
  `BCAB` (LK сам починил блок) ⇒ **LK запускается**; seccfg == сток
  (`12a94a3f…`), зеркало == эталон (`2374972d…`, locked=1).
- **Дефект методики:** при подключённом USB preloader ждёт DA и НЕ продолжает
  загрузку. Поэтому все «нет Android, висит 0006» — артефакт теста, а не факт.
  Правильно: после ребута СРАЗУ выдернуть кабель, подождать 60-90 с, вставить
  и смотреть `lsusb` (`2046` = Android).
- План: (1) проверить сток по правильной схеме; (2) если грузится — вернуть
  unlock и проверить так же; (3) если сток не грузится — искать суперблок
  t-base (`K400RPMB`) по всему RPMB (H2).

## 21. База подтверждена, H2 опровергнута (2026-10-24 23:05)

- После откатa + правильного включения (кабель выдернут) Android стартует:
  `22d9:2046`, Product RMX3630, serial SG7DCQW8X8ONCI9T; USB = только MIDI,
  `adb devices` пуст.
- **H2 опровергнута**: к этому моменту сделано 3 аутентифицированные записи в
  RPMB (счётчик сдвинут), и Android всё равно грузится ⇒ запись в RPMB не
  ломает TEE/FBE.
- Все прежние «нет загрузки» — артефакт подключённого кабеля (preloader ждёт DA).
- Добавлен `UNLOCK_NO_REBOOT=1` в `rpmb_unlock_mirror.py` (не перезагружать,
  чтобы успеть выдернуть кабель). Следующий шаг — вернуть unlock и проверить
  загрузку по правильной схеме, затем патчить `boot_a` под ADB.

## 22. Настоящий unlock в LK стирает данные (2026-10-24 23:25)

Дизасм `0x500076A8` (fastboot unlock): `0x5003266C` (set_lock_state→3) →
**`0x50007C9C` (wipe userdata/metadata)** → `0x50054744(1,1)` (mirror sboot=1,
locked=0). Мы вайп не делали и писали sboot=0. Если ключи FBE привязаны к
состоянию блокировки — именно это и даёт цикл при разлоченной загрузке
(пара вибраций = старт → сброс).

Проверка: (1) `reserve1_probe.py` — NoBoot-счётчик (растёт ли bootcount);
(2) с согласия пользователя — стереть userdata+metadata и повторить загрузку.

## 23. План: вайп userdata+metadata (2026-10-24 23:40)

Симптом при разлоченной загрузке: «старт → сброс» (двойная вибрация), цикла нет.
Данные не нужны ⇒ повторяем штатный unlock: `0x50007C9C` стирает
userdata/metadata. Инструмент `wipe_and_unlock.py`
(`WIPE_GO=1 ./run_wipe_and_unlock.sh`, с `OPLUS_PATCH_ERASE_DENY=1`):
ERASE-FLASH metadata (32 МБ) + userdata (полный unmap, fallback — обнуление
первых 16 МБ), затем при необходимости дозапись unlock-состояния, без ребута.
Затем вручную: кабель выдернуть → Power 10 с → Power 3 с → 90–120 с → вставить
кабель → `lsusb` (ожидаем 2046; первый старт после вайпа 2–3 мин).

## 24. ПРОРЫВ: Android + ADB (2026-10-25 00:05)

После вайпа metadata(1 МБ)+userdata(16 МБ) и включения без кабеля:
`22d9:2769`, интерфейс `255/66/1 = ADB Interface`, `adb devices` →
`SG7DCQW8X8ONCI9T unauthorized`. Гипотеза FBE-привязки к lock_state
подтвердилась (без вайпа не грузилось, с вайпом — грузится).

Дальше: патч boot-рамдиска (`boot_ramdisk_patch.py`): header v3/v4, рамдиск
LZ4-legacy → свой кодек + cpio; правим `system/etc/ramdisk/build.prop`
(`ro.adb.secure=0`, `ro.debuggable=1`, `persist.sys.usb.config=adb`) и кладём
`/adb_keys`. Итог `/home/musin/boot_patched.img` (0x167c000 B).
Прошивка: `FLASH_GO=1 ./run_flash_boot_patched.sh` (полный бэкап boot_a + readback).
Откат: `BOOT_RESTORE=<backup> FLASH_GO=1 …`.

## 25. Патч пересобран из реального boot_a (2026-10-25 00:20)

`docs/notes/rmx3630-lk/boot.img` — ДРУГАЯ (старая) сборка: kernel_size
0x1376ecd vs реальный **0x137dd75**, ramdisk offset 0x1378000 vs **0x137f000**,
fingerprint …1725286517508 vs …1740487296106. Свежий бэкап boot_a
(md5 356320597c88669f032e9736e5f906ce) ≠ старый файл (10f3576a…).
Патч пересобран из `/home/musin/boot_a_backup_20261024_225224.img`:
образ 0x1683000 B, props adb-патча на месте, `/adb_keys` 714 B.
Правило: образ для прошивки собирать только из свежего бэкапа и сверять
`kernel_size`.

## 26. Причина bootloop: затёртая встроенная vbmeta (2026-10-25 00:35)

`boot_a` v4 содержит встроенную vbmeta (`AVB0` @0x1513000) и AVB-футер в конце.
Первый патч (LZ4 0x3035af, образ 0x1683000) накрыл vbmeta → libavb читал мусор
→ жёсткий сбой → цикл.

Исправлено `build_boot_gzip.py`: рамдиск gzip -9 (0x15acb6) влезает в штатный
слот 0x194000, байты от 0x1513000 до конца скопированы из стока побайтно
(vbmeta+footer целы), меняется только рамдиск. Патч: ro.adb.secure=0,
ro.debuggable=1, persist.sys.usb.config=adb, /adb_keys.
Ответы: ключ в userdata записать нельзя (FBE), vbmeta патчить нельзя (подпись).

## 27. gzip-boot загрузился, но adb unauthorized (2026-10-25 00:50)

Прошитый образ (gzip-рамдиск, vbmeta на месте) — **грузится**, цикла нет:
значит hash mismatch в orange-state допускается, и структура верна.
Но правка `system/etc/ramdisk/build.prop` не применилась (файл не читается
init'ом). Свойства перенесены в **`/prop.default`** (читается first-stage init
раньше системного build.prop; `ro.*` write-once): ro.adb.secure=0,
ro.debuggable=1, ro.secure=0, persist.sys.usb.config=adb.
Образ: cpio 0x300690 → gzip 0x15ad19, слот ок, vbmeta/футер стоковые.

## 28. GKI-механизм force_debuggable (2026-10-25 01:00)

По разбору AOSP (`/home/musin/aia`): `system/etc/ramdisk/build.prop` в GKI
читается только на `ro.bootimage.build.date*`/`fingerprint`; `/prop.default` и
`/default.prop` с Android 10 не читаются вовсе. Штатный путь — маркер
**`/force_debuggable`** + **`/adb_debug.prop`**: first-stage init копирует их в
`/second_stage_resources/`, вторая стадия грузит `adb_debug.prop` с наивысшим
приоритетом, но только при `verifiedbootstate == orange` (у нас lock=3).
Образ пересобран: +force_debuggable, +adb_debug.prop (ro.adb.secure=0,
ro.debuggable=1, ro.force.debuggable=1, persist.sys.usb.config=adb),
+prop.default (legacy), +adb_keys. gzip 0x15ad50, vbmeta/футер стоковые.

## 29. Реверс init/LK: force_debuggable подтверждён (2026-10-25 01:20)

- `init` в рамдиске — только first stage: при наличии `/force_debuggable` (корень
  рамдиска) копирует `/adb_debug.prop` → `/debug_ramdisk/adb_debug.prop` и
  `/userdebug_plat_sepolicy.cil` → `/debug_ramdisk/…`; отсутствие .cil только
  лишает userdebug-sepolicy (свойства всё равно грузятся). `verifiedbootstate`
  в этой ветке НЕ проверяется.
- Загрузка свойств — во второй стадии (`/system/bin/init`): `/debug_ramdisk/adb_debug.prop`
  грузится ПОСЛЕДНИМ и перетирает `ro.*` из `/system/build.prop`; `/prop.default`
  читается только в recovery (поэтому v3 не сработал).
- LK при lock=3 гарантированно ставит `verifiedbootstate=orange`,
  `device_state=unlocked`, а `avb_slot_verify` вызывается с
  ALLOW_VERIFICATION_ERRORS (bit0) → hash mismatch встроенной vbmeta не фатален.
- Следующий шаг: прошить v4 (md5 76e089fa4aadc1bc17f931a50ccf33d4) и проверить
  `adb devices`. v4, судя по логам, ещё не прошивался (последний flash — v2).

## 30. v4 не сработала: нужен userdebug_plat_sepolicy.cil (2026-10-25 01:40)

В `FirstStageMain`: setenv("INIT_FORCE_DEBUGGABLE") вызывается только если
удались ОБЕ копии (adb_debug.prop И userdebug_plat_sepolicy.cil). На user-сборке
второго файла нет → env не ставится → вторая стадия не грузит adb_debug.prop.
Исправление v5: патч 4 байт в init — 0x2F6D14 `tbz w19,#0,0x2F6DA4` →
`b 0x2F6DA4` (setenv всегда; use_userdebug_policy остаётся false, файла нет).
Образ v5 md5 f0c1674243f465d9bb363a45642d2117, ramdisk 0x15ad50, vbmeta цела.

## 31. system (EROFS) извлечён, init разобран (2026-10-25 00:10)

- `system_a` = **EROFS** (магия `0xE0F5E1E2` по +0x400), 22 extent'а, 0.89 ГБ;
  дамп `/home/musin/system_a.erofs` (md5 `f66645e4…`), распакован в `/tmp/sysroot`.
- LP-разметка: контейнер с `0x1000`, заголовок `0x3000`, дескрипторы на `0x50`,
  таблицы от `header_size`; разделы `system_a`, `vendor_a`, …
- `/system/bin/init` (3 085 160 B): строки `/force_debuggable` (0x17A49),
  `/prop.default` (0x2850B, только recovery), `/debug_ramdisk/adb_debug.prop`
  (0x337B7/0x338EE, xref 0x156FE4). Вторая стадия грузит adb_debug.prop при
  `access(R_OK)==0`, но между ними вызов `0x2D81A0` и ветка «нет прав» (0x158C80).
- `ro.adb.secure=1` — в `/system/build.prop` (стр. 121); adbd — в
  `/system/apex/com.google.android.adbd.apex`.
- На устройстве props не применились → гипотеза №1: первую стадию исполняет
  `init` из `vendor_boot_a` (перекрывает наш из boot-рамдиска). Следующий шаг —
  дамп `vendor_boot_a` и проверка, есть ли там `init`.
- Handoff: `docs/notes/HANDOFF-2026-10-25.md`.

## 32. Penumbra-survey и обновление доков (2026-10-26 09:10)

- Прочитаны README + все доки penumbra (Download Agent / DA Extensions /
  XML DA Protocol / Seccfg / Carbonara / Heapbait / Kamakiri) и их код
  (heapbait.rs, carbonara.rs). Сравнение — в
  `reverse/re-penumbra-survey-2026-10-26.md`.
- Ключевое: (1) их heapbait-дока говорит packet_size 0x20000, их же код —
  0x2000 (совпадает с нашим резолвером 200EX01); (2) их carbonara-детектор
  на 2710/doogee держится только на ASCII-строке, r6-кламп `e3560101` не
  покрыт (наш баг из gate.md подтверждён у них); (3) их sled
  декларационный (HEAP_SIZE=0x32000000), у нас — лотерея/scratch.
- Внесены errata: re-heapbait-vuln (+XML-escape как самостоятельный вектор,
  packet_len корроборирован), re-heapbait-stabilize (sled math),
  re-sec-dispatch / re-da2-readregister / re-da_br-readregister (2710:
  EFUSE 0x40005C20/0x40005D04, READ/WRITE-REGISTER отсутствуют),
  re-preloader-daa-lk (2710 base 0x200F00), re-tee-efuse (2710 UNISOC),
  re-da1-2710-daswap (трейлер-кросс 0x3C, блок-карта S/K27),
  re-consistency-audit (строка 0x4000599c — только 200EX01).
- #409: ответ на 6411274575 опубликован (комментарий 6411816675, ea29ia):
  карта блоков подтверждена, S живёт в 5 местах (2 preloader'а, 2 DA2,
  .auth-стабы), исправлен наш кросс-байт 0x7C→0x3C, честная оговорка про
  неполную офлайн-верификацию PSS.
