# RE: DA2 из AllInOne-контейнера DA_BR.bin — CMD:READ-REGISTER / CMD:WRITE-REGISTER

Дата: 2026-10-24. Контейнер: `/home/musin/firmware/extracted/IMAGES/download_agent/DA_BR.bin` (785024 байт,
загружается на живом устройстве RMX3630). Метод: парсинг по коду mtkclient
(`daconfig.py::DA/EntryRegion`, `xmlflash/xml_lib.py::upload_da1/2`), дизассемблер capstone, `CS_MODE_ARM`.

## TL;DR

**Извлечённый из DA_BR.bin DA2 байт-в-байт совпадает с уже отреверсенным `da2_oplus.bin`** —
расхождение только в хвостовых 0x100 байтах подписи. Т.е. вся методика и все адреса из
`re-sec-dispatch.md` §2.3 и `re-da2-readregister.md` **напрямую применимы к живому устройству**:
`da2_oplus.bin` и есть DA_BR-DA2. Гипотеза «на устройстве крутится другая сборка» **опровергнута**.

## 1. Извлечение DA2 из контейнера (proven)

Парсинг идентичен mtkclient `parse_da_loader` (daconfig.py:130+):

* заголовок 0x68: `MTK_DOWNLOAD_AGENT` + `MTK_DA_v6_2024-09-02 22:21:09` → `v6=True`;
* `count_da = 1` @0x68; DA-запись @0x6C, размер 0xDC (по `\xDA\xDA`-детекту: old_ldr=False);
* DA-запись: magic=0xDADA, hw_code=0x1208, hw_sub=0x8A00, hw_ver=0xCA00; entry_region_count=3;
* таблица EntryRegion (buf, len, addr, offset, sig):

| # | buf (file off) | len | addr (VA) | sig_len |
|---|---|---|---|---|
| 0 | 0xBC | 0x689FC | 0x200000 | 0x100 |
| 1 | 0xBC | 0x689FC | 0x200000 | 0x100 |
| 2 | **0x68AB8** | **0x56FC8** | **0x40000000** | 0x100 |

mtkclient берёт DA2 как `file[region[2].m_buf : +m_len]` (`xml_lib.py:419,429`), т.е.

* **file-внутри-контейнера offset DA2 = 0x68AB8, размер = 0x56FC8** (последние 0x100 — подпись,
  рабочий образ = 0x56EC8 = 356296 байт, ровно как у `da2_oplus.bin`).
* VA-база = 0x40000000 (region[2].m_start_addr) → **VA = file-offset-в-DA2 + 0x40000000** (подтверждено).

**Доказательство идентичности:** `cmp` извлечённого DA2 с `docs/notes/rmx3630-da2/da2_oplus.bin`
даёт отличия **только в 0x56EC8–0x56FC7** — это и есть 0x100-байтовый sig-хвост, отсутствующий
(зануленный) в ранее отреверсенном файле. Все 356296 байт кода/данных идентичны.

Копия извлечённого образа: `/tmp/opencode/dabr_da2.bin` (356808 байт, с sig).

Строки, цитированные в постановке: «CMD:READ-REGISTER» на «0x696128» и «0xAA060 контейнер» —
0xAA060 − 0x68AB8 = 0x415A8 (область таблицы имён команд DA2, там `"D-FLASH"`); сами канонические
offset'ы в DA2: `CMD:READ-REGISTER` @0x41488, `da/arg/bit_width` @0x42F9A,
`R/W on this address is forbidden.` @0x42FBF.

## 2. Handler-карта (proven, совпадает с re-sec-dispatch §2.3)

Регистратор `0x400086d4(name, perm, handler)`, свип 0x40001a6c–0x40001e28, голова списка `[0x40054390]`:

| Команда | строка VA | handler VA | условие |
|---|---|---|---|
| CMD:WRITE-EFUSE | 0x40041459 | 0x4000599C | всегда |
| CMD:READ-EFUSE | 0x40041469 | 0x40005A80 | всегда |
| CMD:GET-HW-INFO | 0x40041478 | 0x400064BC | всегда |
| **CMD:READ-REGISTER** | 0x40041488 | **0x40006EEC** | **всегда** (site 0x40001AC4) |
| **CMD:WRITE-REGISTER** | 0x400414FF | **0x4000700C** | гейт @0x40001ADC: `[0x4005455C]==4` → "in read back mode"; `==3` → "do not get oplus permission" (не регистрируется вовсе) |

READ-REGISTER @0x40006EEC (disasm подтверждён в DA_BR-DA2):

```
0x40006F10  bl 0x4000D0BC        ; mini-XML SAX parse; 0 → err "node path not found"
0x40006F24  get_node("da/arg/bit_width")      ; только существование, значение не читается
0x40006F3C  get_node("da/arg/base_address")   → atoi-hex 0x4000AEF4
0x40006F54  get_node("da/arg/target_file")
0x40006F80  bl 0x40010FB0        ; ★ auth-гейт: cmp r0,#0; beq 0x40006FF8 (forbidden)
0x40006F8C  ldr r0,[sb]          ; прямой *(u32*)base_address; размер жёстко 4 (mov r3,#4)
0x40006FA8  bl 0x4002B330        ; read_reg_core → CMD:UPLOAD-FILE + OK@0x4 + 4 сырых байта
0x40006FF8  (forbidden) movw r0,0x42FBF → "R/W on this address is forbidden.", ret 0xC0010001
0x40006FC0/6FDC  ldr r0,[0x40054314] → "Required XML node path not found. Check command string."
```

WRITE-REGISTER @0x4000700C — та же структура: `da/arg/{bit_width, base_address, source_file}`
(строка 0x400417CC), гейт `bl 0x40010FB8` @0x400070A0, успех = `*(u32*)base = первые 4 байта
source_file` (bl 0x4002AE8C — download-file flow).

## 3. Auth-гейты (proven, bytes в DA_BR-DA2 проверены)

| Гейт | VA | file offset в DA2 | байты (сейчас) | патч (разблокировка) |
|---|---|---|---|---|
| READ-REGISTER | 0x40010FB0 | **0x10FB0** | `0000A0E3 1EFF2FE1` (`mov r0,#0; bx lr`) | `0100A0E3 1EFF2FE1` (`mov r0,#1; bx lr`) |
| WRITE-REGISTER | 0x40010FB8 | **0x10FB8** | `0000A0E3 1EFF2FE1` | та же |

Альтернатива: NOP `bl`+`cmp`+`beq` на sites 0x40006F80–0x40006F88 и 0x400070A0–0x400070A8
(site-байты подтверждены: `0A2800EB 000050E3 1A00000A` / `C42700EB 000050E3 1E00000A`).

**ВАЖНО для рантайм-патча:** эти offset'ы — относительно начала DA2-образа, т.е. абсолютный
file offset в DA_BR.bin = 0x68AB8 + offset. Но при рантайм-патче (mtkclient patch_da) правится
сам образ DA2, так что DA2-офсеты и есть целевые.

## 4. Совпадение runtime-патчей mtkclient с DA_BR-DA2 (proven)

Образ идентичен da2_oplus.bin ⇒ все применяемые mtkclient адреса валидны и для живой загрузки:

| Адрес | Что | Проверка байтов в DA_BR-DA2 |
|---|---|---|
| 0x40007ABC | cust_security_verify_sec_policy | пролог `704C2DE9 10B08DE2...` — функция, OK |
| 0x400103DC | oplus_security_verify_sec_policy | пролог `F04D2DE9 18B08DE2 08D04DE2` — функция, OK |
| 0x400416BF | DA.SLA (строка "ENABLED"/чек) | `45 4E 41 42 4C 45 44 00` = "ENABLED\0" @0x416BF, OK |
| 0x4005455C | g_oplus_auth_status (глобал) | код-ссылки @0x40001ADC (`movw r0,#0x455C; movt 0x4004; ldr r0,[r0]`), OK |

Реверс-методика полностью применима; настоящие READ/WRITE-REGISTER гейты в этом билде —
именно 0x40010FB0 / 0x40010FB8 (по одному вызову каждый: 0x40006F80 / 0x400070A0).

## 5. Почему mtkclient получает "Required XML node path not found"

Схема DA (proven по дизасму, строки 0x40042F9A/2FAB/41A27):

```
da/arg/bit_width     — обязателен, значение игнорируется
da/arg/base_address  — обязателен, парсится atoi-hex
da/arg/target_file   (READ) / da/arg/source_file (WRITE) — обязателен, строка
```

mtkclient `create_cmd` (xml_cmd.py:18) + `cmd_read_reg` дают ровно эту структуру:
`<?xml...?><da><version>1.0</version><command>CMD:READ-REGISTER</command><arg><bit_width>32</bit_width><base_address>0x10007024</base_address><target_file>MEM://0x8000000:0x4</target_file></arg></da>` —
байт-в-байт совпадает с ожиданиями DA (отличие `32` vs `0x20` в bit_width не важно — значение не читается).

Ошибка 0x40041748 «Required XML node path not found. Check command string.» (через таблицу
[0x40054314]) выдаётся **только** в двух случаях: (а) XML не распарсился (`0x4000D0BC` → 0),
(б) один из трёх get_node вернул NULL. Поскольку (б) исключён (схема совпадает proven), а
«другая сборка DA» опровергнута (§1), причина — **(а): до парсера доходит не тот XML**, т.е.
транспортный/синхронизационный уровень: известная потеря первого bulk-IN после SLA
(xml_lib.py::send_command, комментарий про EIO и retry), десинк get_command_result/read_register
(read_register при `cmd != ''` просто возвращает False, а напечатанный `self.error(result)` — это
ответ DA предыдущего/искажённого обмена). Прямого достижения forbidden-пути при этом нет:
при корректно доставленном XML DA отвечал бы «R/W on this address is forbidden.», а не
node-path-not-found. → Рекомендация: перехватить сырые RX-байты DA (или лог xsend/xread) в момент
команды; после патча гейтов ожидать успешный UPLOAD-FILE flow.

## 6. Proven / inferred

- proven: контейнер — DA v6, count=1; DA2 @file 0x68AB8, len 0x56FC8 (с sig 0x100), VA-база
  0x40000000; DA_BR-DA2 ≡ da2_oplus.bin (все 356296 байт); handler-карта и гейты
  0x40010FB0/0x40010FB8 (заглушки `mov r0,#0; bx lr` в байтах); XML-схема `da/arg/{...}`;
  условия ошибки «node path not found» (parse-fail или NULL-node); совпадение всех 4 runtime-патчей.
- inferred: точный механизм искажения XML на транспортном уровне (канал/синхронизация) — требует
  байтового перехвата; поведение `[0x4005455C]` при live-фазе auth (уровень oplus-permission).
