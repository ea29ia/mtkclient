# DA2 (OPLUS, da2_oplus.bin): CMD:READ-REGISTER / CMD:WRITE-REGISTER

Бинарник: `/home/musin/firmware/extracted/IMAGES/da2_oplus.bin`, 356296 байт.
VA = file offset + 0x40000000 (подтверждено парами строка↔код, см. re-write-chain.md).

**Важно (proven, поправка к исходной посылке):** бинарник — **ARM (A32), НЕ Thumb**.
Все функции декодируются чисто в `CS_MODE_ARM` (пролог `e92d4bf0 = push {r4-r9,ip,fp,lr}` и т.п.).
В Thumb те же байты дают мусор — поэтому начальный поиск "ldr r0,[pc,...]" по пулам ничего не дал:
ссылки на строки сделаны парами **movw/movt** (`movw r1,#0x2f9a; movt r1,#0x4004`), а не literal pool'ами.

## 1. Карта handler'ов (proven)

Регистрация команд — функция около `0x40001a6c` (регистратор `0x400086d4(name, perm_str, handler)`,
таблица — односвязный список, голова `[0x40054390]`, элемент 0x14 байт: `{next, perm, name, 0, handler}`):

| Команда | Строка (VA) | Handler (VA) | Условие регистрации |
|---|---|---|---|
| CMD:WRITE-EFUSE | 0x40041459 | 0x4000599c | всегда |
| CMD:READ-EFUSE | 0x40041469 | 0x40005a80 | всегда |

> **ERRATA (2026-10-26):** таблица выше — только для 200EX01 (`da2_oplus.bin`). На 2710EX01
> хендлеры другие (WRITE-EFUSE `0x40005C20`, READ-EFUSE `0x40005D04`, регистрация по строкам
> через `bl 0x400083DC`), а сами команды READ/WRITE-REGISTER на 2710 **отсутствуют** —
> on-device digest-вычисления через READ-REGISTER на 2710 невозможны. Детали:
> `/tmp/opencode/verify/efuse2710.md`, `re-penumbra-survey-2026-10-26.md`.
| CMD:GET-HW-INFO | 0x40041478 | 0x400064bc | всегда |
| **CMD:READ-REGISTER** | 0x40041488 | **0x40006eec** | **всегда** |
| **CMD:WRITE-REGISTER** | 0x4004150a | **0x4000700c** | **только если `[0x4005455c] ∉ {3,4}`** |
| CMD:WRITE-PARTITION | 0x40041512 | 0x40002034 | то же условие |
| CMD:WRITE-FLASH | 0x40041526 | 0x40002e60 | то же условие |

Гейт регистрации WRITE-REGISTER (`0x40001adc`):
- `[0x4005455c] == 4` → лог "[oplus] in read back mode, can not register cmd_write_register" (0x400414bf), WRITE-REGISTER не регистрируется;
- `[0x4005455c] == 3` → лог "[oplus] do not get oplus permission" (0x4004149a), и вообще не регистрируется ни WRITE-REGISTER, ни WRITE-PARTITION/WRITE-FLASH и далее;
- иначе — регистрируется.
`[0x4005455c]` — уровень oplus-permission, заполняется из auth-данных (код около 0x40010038/0x400105b8, inferred).

Если команда не найдена в таблице, диспетчер (`0x400087dc…0x40008a90`) отвечает `ERR!UNSUPPORTED`/`CMD:UNKNOWN` — это **не** та ошибка, что видит mtkclient.

## 2. Разбор READ-REGISTER @ 0x40006eec (proven)

```
0x40006eec  push {r4-r9,ip,fp,lr}; ...
; r6 = transport-ctx ([ctx]=recv, [ctx+4]=send), r4 = буфер с XML-запросом
0x40006f10  bl 0x4000d0bc          ; XML-parse буфера (mini-XML, SAX); r0=doc
0x40006f18  cmp r0,#0 → 0 → err    ; ПАРС-ОШИБКА ДАЁТ ТУ ЖЕ ОШИБКУ "node path not found"!
0x40006f24  get_node(doc,"da/arg/bit_width")     ; 0x40001e48
0x40006f3c  get_node(doc,"da/arg/base_address")  ; → r7 = ТЕКСТ узла
0x40006f54  get_node(doc,"da/arg/target_file")   ; → r8 = ТЕКСТ узла
0x40006f78  bl 0x4000aef4          ; atoi-hex: "0x10007024" → 0x10007024 (поддержка 0x/дец/минуса)
0x40006f80  bl 0x40010fb0          ; ★ auth-чек: `mov r0,#0; bx lr` — заглушка, всегда 0
0x40006f88  cmp r0,#0; beq 0x40006ff8  ; r0==0 → путь "forbidden"
; --- путь успеха (недостижим в данной сборке): ---
0x40006f8c  ldr  r0,[sb]           ; value = *(u32*)base_address  (прямой CPU-load по адресу!)
0x40006fa8  bl  0x4002b330         ; read_reg_core(ctx, target_file, &value, 4, "0x10007024")
```

Ключевые факты:
- **`bit_width` проверяется только на существование, значение не парсится** (нигде не читается). Размер чтения жёстко `4` байта (`mov r3,#4` @0x40006fa0).
- `base_address` — единственный реально используемый числовой аргумент; читается **прямым `ldr` по VA** (т.е. адрес должен быть отображён в адресное пространство DA, иначе data abort/зависание — inferred caveat).
- `target_file` — просто имя файла для ответа (xml-unescape `&quot;`/`&amp;` в 0x4002aba8); формат `MEM://...` не парсится, любая строка.
- **Forbidden-таблицы адресов НЕТ.** Строка `"R/W on this address is forbidden."` (0x40042fbf) — единственный rejection-путь обоих handler'ов, и он срабатывает **всегда**, т.к. гейт `0x40010fb0`/`0x40010fb8` — заглушки `00 00 a0 e3  1e ff 2f e1` (`mov r0,#0; bx lr`), а успех требует **ненулевого** возврата (proven; каждый вызывается ровно из одного места — 0x40006f80 и 0x400070a0).
- Ошибка "Required XML node path not found. Check command string." (0x40041748, через таблицу 0x40054314) выдаётся в двух случаях: (а) любой из трёх get_node вернул NULL, (б) **XML вообще не распарсился** (`0x4000d0bc` вернул 0 → тот же error-путь 0x40006fdc). Т.е. наблюдаемая mtkclient ошибка может означать и parse-failure, а не только отсутствие узла.

Ответ (read_reg_core @ 0x4002b330, тот же протокол, что у остальных файловых команд; mtkclient-совместимо):
1. `CMD:UPLOAD-FILE` XML по шаблону 0x4004ddff:
   `<checksum>CHK_NO</checksum><info>0x10007024</info><target_file><как в запросе></target_file><packet_length>0x…</packet_length>`
   (info = строка base_address, т.к. 5-й аргумент передан; packet_length = глобал `[0x40067a20]`, mtkclient его игнорирует).
2. `OK@0x4` — announce длины (4 байта).
3. handshake `OK`-ack, затем 4 **сырых байта** значения регистра (LE) чанками по `min(4, [0x40067a20])` с ack после каждого.

## 3. Разбор WRITE-REGISTER @ 0x4000700c (proven)

Идентичная структура:
- `get_node("da/arg/bit_width")` — только существование;
- `get_node("da/arg/base_address")` → r7, парсится `0x4000aef4` → r8 = адрес;
- `get_node("da/arg/source_file")` (0x400417cc) → sb = имя файла с данными;
- `bl 0x40010fb8` — та же заглушка `mov r0,#0` → `beq 0x40007128` → **всегда forbidden**.

Успешный путь: `bl 0x4002ae8c(ctx, source_file, &out1, &out2, base_address_str)` — это generic
"скачать файл с хоста": DA шлёт `CMD:DOWNLOAD-FILE` XML (шаблон 0x4004dc6a:
`<checksum>%s</checksum><info>%s</info><source_file>%s</source_file><packet_length>0x%x</packet_length>`),
хост (mtkclient `upload()`) заливает данные. Затем в handler'е:

```
0x400070dc  ldr r0,[sp,#0xc]   ; указатель на принятые данные
0x400070e4  ldr r0,[r0]        ; первые 4 байта файла
0x400070e8  str r0,[r8]        ; *(u32*)base_address = value
```

Т.е. **пишутся первые 4 байта содержимого source_file** (little-endian u32). `bit_width` снова игнорируется.

## 4. Готовый XML (mtkclient-совместимый; соответствует тому, что уже шлёт xml_cmd.py)

Чтение (0x10007024, 4 байта):
```xml
<?xml version="1.0" encoding="utf-8"?><da><version>1.0</version><command>CMD:READ-REGISTER</command><arg><bit_width>0x20</bit_width><base_address>0x10007024</base_address><target_file>MEM://0x8000000:0x4</target_file></arg></da>
```
Запись (значение `X` передаётся содержимым файла при ответе DA `CMD:DOWNLOAD-FILE`):
```xml
<?xml version="1.0" encoding="utf-8"?><da><version>1.0</version><command>CMD:WRITE-REGISTER</command><arg><bit_width>0x20</bit_width><base_address>0x10007024</base_address><source_file>MEM://0x8000000:0x4</source_file></arg></da>
```
(далее standard flow: `xml_lib.write_register` → `if type(result) is DwnFile: self.upload(result, data)`,
где `data` = 4 байта LE со значением; для "выставить биты[3:0]=3" без чтения — только если прочие биты
известны/безопасны, иначе нужен read-modify-write, но чтение заблокировано, см. ниже.)
`bit_width` можно задать любым — значение не используется (proven).

## 5. Почему не работает и что с этим делать

1. **Оба handler'а в этой сборке всегда отвечают `"R/W on this address is forbidden."` (0xC0010001)** —
   auth-гейт `0x40010fb0`/`0x40010fb8` — заглушки, возвращающие 0, а ветка успешного пути требует ≠0
   (proven). Патч для разблокировки: в file offset `0x10fb0` и `0x10fb8` положить
   `01 00 a0 e3  1e ff 2f e1` (`mov r0,#1; bx lr`) — 2×8 байт; либо NOP-нуть `bl`+`cmp`+`beq`
   в 0x40006f80–0x40006f88 и 0x400070a0–0x400070a8.
2. **WRITE-REGISTER к тому же может быть вообще не зарегистрирован**, если oplus-permission
   `[0x4005455c]` ∈ {3,4} (read-back mode / нет oplus permission) — тогда DA ответит
   `ERR!UNSUPPORTED`, а не forbidden (proven; значение переменной зависит от auth-фазы — inferred).
3. Ошибка mtkclient **"Required XML node path not found"** при данной схеме не объясняется
   отсутствием узлов: схема `da/arg/{bit_width,base_address,target_file|source_file}` совпадает
   байт-в-байт с ожиданиями DA (proven). Поскольку тот же текст ошибки выдаётся и при неудачном
   XML-парсе (`0x4000d0bc` → 0), вероятные причины (inferred, требует проверки в логе байтов):
   - до handler'а запрос не дошёл в ожидаемом виде / канал синхронизации другой;
   - проверялась не эта сборка DA (фактически загруженный DA2 иной);
   - при ручных пробах узел/декларация отличались.
   Рекомендация: перехватить сырые байты RX-буфера DA (или сравнить с эталоном из шаблонов выше).

## 6. Сводка: proven / inferred

- proven: ARM-режим (не Thumb); адреса и семантика handler'ов 0x40006eec/0x4000700c; обязательные
  узлы XML; игнорирование bit_width; фикс. размер 4 байта; чтение = `*(u32*)addr`, запись =
  `*(u32*)addr = first4(source_file)`; ответ UPLOAD-FILE/запрос DOWNLOAD-FILE и формат `OK@0x<len>`;
  заглушки auth → всегда forbidden; отсутствие forbidden-таблицы адресов; условная регистрация
  WRITE-REGISTER.
- inferred: смысл `[0x4005455c]` (oplus permission level); значение/происхождение глобала
  `[0x40067a20]` (packet_length в шаблоне — mtkclient его не использует); причина наблюдавшейся
  ошибки "node path not found" у mtkclient.
