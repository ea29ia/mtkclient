# Q1/Q2 round 2: LK ground truth — сборка initrd и `verifiedbootstate`

Дата: 2026-10-25. Устройство не подключено, DA не запускался, ничего не флешилось.
Всё ниже — статический разбор `docs/notes/rmx3630-lk/lk_payload.bin`
(935 424 B, sha256 `e7c857896bfe83966595dc61bea8ced5ef6ad0d6dcf57f7ec5a9892eabd8c763`).

Инструменты: `radare2 -a arm -b 64` и `aarch64-linux-gnu-objdump -D -b binary -m aarch64`
(оба лога — §9). Разбор `init` (Q2, `re-init-prop-gate.md`) здесь **не перепроверяется**,
он принимается как данность.

---

## 0. TL;DR — четыре вердикта

| # | Вопрос | Вердикт | Confidence |
|---|---|---|---|
| 1 | Порядок initrd и чей `/init` попадает в rootfs | **`[vendor_boot cpio]` затем `[boot cpio]` вплотную, `initrd-start = 0x66F00000`, bootconfig по `0x66F00000+0x23BFA46`. Побеждает `/init` из boot-рамдиска (REG поверх LNK). Q1 = FALSE, A прав.** | высокая |
| 2 | Кто и когда пишет `androidboot.verifiedbootstate=` | **Пишет `0x50053F3C` (`cmdline_append`) в реальном boot-пути; enum `0=green,1=yellow,2=orange,3=red`; `lock_state==3 ⇒ 2 (orange)` в `0x50053ACC/0x50053AD4`. Сеттер `0x50053F6C` — тупой `str w0,[0x500C4FA8]`, три вызова; «последняя запись lock==3→2» подтверждается по порядку исполнения, но не по порядку адресов.** | высокая (код) / средняя (что lock==3 в рантайме) |
| 3 | `img_auth_required` — та же защёлка? Покрывает ли vendor_boot? | **Да, ключ тот же `(sboot_state, lock_state)`, но таблица политики `0x500EDDC8` — в .bss (23×0x30), статически не читается. `vendor_boot` верифицируется ФЛАГАМИ из строки `"boot"`/`"recovery"`, отдельной строки для vendor_boot нет — т.е. толерантность та же, что у boot.** | высокая (ключ/флаги) / низкая (значения таблицы) |
| 4 | v6 (оба рамдиска + `/force_debuggable`) даст `device`? | **Только если `verifiedbootstate == orange`. Предикат `access()`+`setenv` v6 снимет, но второй гейт `IsDeviceUnlocked()` не трогает; orange в v6 не появляется.** | высокая |

Одной строкой: **v6 в текущем виде не может включить adb; чинить надо не рамдиски, а
`verifiedbootstate` (т.е. фактический `lock_state==3`, читаемый LK, либо cmdline).**

---

## 1. Артефакт и база загрузки (правка к заданию)

Задание говорит «load base 0x40000000». Это **неверно**: payload грузится по
**0x50000000**. Доказательство — 64-битная таблица литералов на payload-offset `0xAC700`:

```
payload 0xAC700: 42 c6 fa 50 00 00 ff ff   -> 0xFFFF000050FAC642
payload 0xAC708: fb c5 fa 50 00 00 ff ff   -> 0xFFFF000050FAC5FB
payload 0xAC710: d6 c5 fa 50 00 00 ff ff   -> 0xFFFF000050FAC5D6
payload 0xAC718: 20 c6 fa 50 00 00 ff ff   -> 0xFFFF000050FAC620
```

Строки по этим адресам (payload 0xAC5D6…): `androidboot.verifiedbootstate=orange`,
`=yellow`, `=red`, `=green`. `ptr − 0xAC5D6 = 0x50000000` для всех четырёх →
**VA = payload_offset + 0x50000000**. (Совпадает с `re-lk-seccfg.md` §1; там же сказано,
что первый проход делался по 0x40000000 — отсюда и путаница в задании.)

Контейнер: `lk.img` = MTK-заголовок 0x200 + raw payload 0xE4600 (`0x50000000…0x500E4600`),
далее cert1/cert2/bl2_ext/aee/dtb. Всё, что выше `0x500E4600` (например `0x500EDDC8`,
`0x5009408F8`) — **.bss, в файле нули**.

Ниже все адреса — VA при базе 0x50000000.

---

## 2. Q1 — сборка initrd

### 2.1 Кто и куда копирует (главное доказательство)

`boot_linux_from_storage` (строковый якорь `0x50092259`, прологи — лог §9.10):

```asm
0x5000d9b8  mov  x25, 0x66f00000 ; movk x25,0xffff,lsl 48   ; x25 = 0xFFFF000066F00000
0x5000d9c4  str  x25, [sp, 0x78]                            ; курсор назначения = 0x66F00000
...
0x5000ddac  ldr  x19, [sp, 0x78]        ; x19 = 0x66F00000
0x5000ddb0  cmp  w0, 3                  ; w0 = lk boot mode (0x5000a144)
0x5000ddb4  b.lo 0x5000dde4
0x5000ddb8  bl   0x5000a678             ; src = vendor ramdisk addr
0x5000ddbc  mov  x24, x0
0x5000ddc0  bl   0x5000a7a0             ; size = vendor_ramdisk_size
0x5000ddc4  mov  w2, w0
0x5000ddc8  mov  x0, x19                ; dst = 0x66F00000
0x5000ddcc  mov  x1, x24
0x5000ddd0  bl   0x5006c9c8             ; memcpy(0x66F00000, vendor, vendor_size)
0x5000ddd4  bl   0x5000a7a0             ; size снова
0x5000ddd8  ldr  x8, [sp, 0x78]
0x5000dddc  add  x19, x8, w0, uxtw      ; cursor = 0x66F00000 + vendor_size
0x5000dde0  str  x19, [sp, 0x78]
0x5000dde4  bl   0x5000a5bc             ; src = boot ramdisk addr
0x5000dde8  mov  x24, x0
0x5000ddec  bl   0x5000a714             ; size = boot ramdisk_size
0x5000ddf0  mov  w2, w0
0x5000ddf4  mov  x0, x19                ; dst = 0x66F00000 + vendor_size
0x5000ddf8  mov  x1, x24
0x5000ddfc  bl   0x5006c9c8             ; memcpy(base+vendor, boot, boot_size)
```

Никакого выравнивания между ними: `add x19, x8, w0, uxtw` — сырой размер.
(Функция `0x5000A7EC` = `align_up(vendor_ramdisk_size, page_size)` существует и
вызывается из `0x5000CC38`, но к этой склейке отношения не имеет — там считаются
адреса для тегов.)

### 2.2 Геттеры (проверка, что это именно те поля)

| функция | читает | смысл |
|---|---|---|
| `0x5000A678` | `[0x50113238] + page_size` | указатель рамадиска vendor_boot-образа |
| `0x5000A7A0` | `*(u32*)0x501129E8` = `vendor_hdr+0x18` | `vendor_ramdisk_size` |
| `0x5000A5BC` | `[0x50113230] + page + align_up(kernel_size+page,page)` | рамадиск внутри загруженного boot.img |
| `0x5000A714` | `boot_hdr+0x0C` (при hv>2) | `ramdisk_size` из boot.img |
| `0x5000A55C` | `*(u32*)0x501129E4` = `vendor_hdr+0x14` | `ramdisk_addr` = **0x66F00000** |
| `0x5000A910` | `vendor_hdr+0x18` + `boot_hdr+0x0C` | **суммарный размер initrd** |

Кэши заголовков: boot-хедер — `bootinfo_from_hdr` (`0x50009FE8`) копирует 0x67C B
в `0x50112350`; vendor-хедер — те же 0x850 B в `0x501129D0` (magic-сравнения
`"ANDROID!"` @ `0x50090EB0` / `"VNDRBOOT"` @ `0x50090EF1`, вызовы `0x5000A01C`/`0x5000A02C`).

### 2.3 Блоб обязан лежать ровно по 0x66F00000

```asm
0x5000db58  add  w3, w21, 0x800        ; w21 = суммарный initrd, +2 KiB под bootconfig
0x5000db60  cmp  w3, 0x4000000         ; LK_RAMDISK_SIZE = 64 MiB
0x5000db68  ...  "%s:%d: ramdisk_map_sz (0x%x) cannot overrun LK_RAMDISK_SIZE (0x%x)"
0x5000dbac  add  x8, x8, 0xfff
0x5000dbb0  and  x24, x8, 0x1fffff000  ; округление до 2 MiB
0x5000dbd4  bl   0x50018a34            ; mem_reserve(size, 0x1000, -1, ...)
0x5000dbd8  mov  w8, 0x66f00000
0x5000dbdc  cmp  x0, x8
0x5000dbe0  b.ne 0x5000dc2c            ; иначе фатально:
                                        ; "ret %s:%d: ramdisk_addr (0x%x) is not taken from mb (0x%llx)"
```

`0x5009227C` = `%s:%d: ramdisk_addr (0x%x) is not taken from mb (0x%llx)\n`,
`w3 = 0x66F00000`. Т.е. весь сплошной блоб (vendor+boot) резервируется одним куском
и **обязан** начаться по 0x66F00000.

### 2.4 initrd-start / initrd-end / bootconfig

```asm
0x5000d578  rev  w8, w22                    ; bswap32(initrd_start)
0x5000d57c  add  x2, x2, 0x73 ; -> 0x50092073 = "linux,initrd-start"
0x5000d58c  str  w8, [sp, 0x40]
0x5000d590  bl   0x5005d4c8                ; fdt_setprop(fdt, node, "linux,initrd-start", &v, 4)

0x5000d5e4  mov  x8, 0x66f00000 ; movk x8,0xffff,lsl 48
0x5000d5ec  add  x1, x8, w27, uxtw         ; x1 = 0x66F00000 + w27 (w27 = суммарный размер)
0x5000d5f4  bl   0x5000b46c                ; bootconfig_build(fdt, dest) -> размер
0x5000d5fc  add  w9, w22, w27              ; start + total
0x5000d600  add  w9, w9, w0                ;   + bootconfig_size
0x5000d608  rev  w9, w9
0x5000d60c  add  x2, x2, 0x8f ; -> 0x5009208f = "linux,initrd-end"
0x5000d624  bl   0x5005d4c8                ; fdt_setprop(..., "linux,initrd-end", ...)
```

`0x5000B46C` действительно пишет по переданному адресу:
`0x5000B798 ldur x0,[x29,-0x18]` (сохранённый arg1) + `0x5000B7B8 bl 0x5006C9C8`
(`memcpy(dest, собранный_bootconfig, w21)`), возвращает `w21` — размер.
Бюджет bootconfig = 0x800 (`0x5000B490 mov w0,0x800`).

Отсюда: **`initrd-start` = `w22` = `x22` = `x26`** (присваивание `0x5000D2E0 mov x26,x22`),
и `initrd-end = start + total + bootconfig`. Так как bootconfig пишется по
`0x66F00000 + total`, а `end` считается как `start + total + bootconfig`, то
**start обязан быть 0x66F00000** — иначе `end` не совпадёт с концом блоба.

### 2.5 Числа для стока

```
vendor_ramdisk_size = 35 835 345 = 0x222CDD1
boot   ramdisk_size =  1 649 781 = 0x192C75
total               = 37 485 126 = 0x23BFA46
vendor   : 0x66F00000 .. 0x6912CDD1
boot     : 0x6912CDD1 .. 0x692BFA46
bootconfig: 0x692BFA46 .. 0x692BFA46+size (<= +0x800)
initrd-start = 0x66F00000
initrd-end   = 0x692BFA46 + bootconfig_size
```

### 2.6 Чей `/init` побеждает

Ядро 5.10.198-android12 распаковывает `[initrd-start, initrd-end)` последовательно
(`init/initramfs.c`): каждый следующий cpio-архив **накладывается** на уже собранный
rootfs. Для совпадающего пути вызывается `clean_path()`:

```c
static void __init clean_path(char *path, umode_t fmode) {
        struct kstat st;
        if (!init_stat(path, &st, AT_SYMLINK_NOFOLLOW) &&
            (st.mode ^ fmode) & S_IFMT) {
                if (S_ISDIR(st.mode)) init_rmdir(path);
                else                   init_unlink(path);
        }
}
```

`do_name()` (regular file) зовёт `clean_path(collected, mode)`: тип существующей
записи (`S_IFLNK`, симлинк `/init -> /system/bin/init` из vendor-рамдиска) не совпадает
с `S_IFREG` → `init_unlink("/init")` → создаётся обычный файл из boot-рамдиска.

Порядок распаковки = порядок в памяти = vendor, затем boot. Последняя запись `/init` —
**regular file 3 143 536 B, sha256 `b8088eb2…`**.

**Вердикт Q1: FALSE.** v5-патч `0x2F6D14` попадал в исполняемый бинарь. Гипотеза A верна,
гипотеза «vendor_boot перекрывает boot» — нет.

### 2.7 Falsifiers для Q1

* `adb shell ls -l /init` → `lrwxrwxrwx … -> /system/bin/init` (тогда порядок/наложение
  иные, и мой вывод неверен);
* `sha256sum /init` = `de409287…` (2 097 128 B, vendor-сборка) вместо `b8088eb2…`;
* в rootfs присутствуют ТОЛЬКО vendor-специфичные файлы и отсутствуют файлы boot-рамдиска
  (`/second_stage_resources`, `/lib/modules` из boot cpio — см. `re-vendor-boot-q1.md` §5);
* если бы LK всё-таки вставлял page-padding между архивами (0x22F байт нулей для нашего
  vendor-размера `0x222CDD1`), ядро ругнулось бы `junk in compressed archive`; наблюдение
  такой ошибки означало бы, что второй архив вообще не распаковался — это единственная
  реальная дыра в выводе (см. §6, confidence).

---

## 3. Q2 — `verifiedbootstate`

### 3.1 Enum: 2 == orange

```asm
0x50053f3c  adrp x8, 0x500c4000 ; ldrsw x8, [x8, 0xfa8]   ; state = *(int*)0x500C4FA8
0x50053f44  cmp  w8, 3
0x50053f48  b.hi 0x50053f5c                                 ; >3 -> ничего не пишем
0x50053f4c  adrp x9, 0x500ac000 ; add x9,x9,0x700          ; таблица 0x500AC700
0x50053f54  ldr  x0, [x9, x8, lsl 3]
0x50053f58  b    0x50018204                                 ; cmdline_append(строка)
```

Таблица `0x500AC700` (payload 0xAC700): `[0]=0x…50FAC642`, `[1]=0x…50FAC5FB`,
`[2]=0x…50FAC5D6`, `[3]=0x…50FAC620`, а строки по этим адресам:

| idx | адрес строки | текст | цвет |
|---|---|---|---|
| 0 | `0x500AC642` | `androidboot.verifiedbootstate=green` | green |
| 1 | `0x500AC5FB` | `androidboot.verifiedbootstate=yellow` | yellow |
| 2 | `0x500AC5D6` | `androidboot.verifiedbootstate=orange` | **orange** |
| 3 | `0x500AC620` | `androidboot.verifiedbootstate=red` | red |

Баннер (`0x50053F78`) это подтверждает независимо:

```asm
0x50053f88  cmp w8, 1 ; 0x50053f8c b.eq 0x50054010   ; 1 -> power-off
0x50053f90  cmp w8, 3 ; 0x50053f94 b.eq 0x50054010   ; 3 -> power-off
0x50053f98  cmp w8, 2 ; 0x50053f9c b.ne 0x50054004   ; НЕ 2 -> return 0
0x50053fa0..0x50053ffc                               ; 2 -> "Orange State\n\n"
                                                      ;      "'t be trusted\n"
                                                      ;      "Press power button to continue"
                                                      ;      "Or, device will power off in %ds"
                                                      ;      mdelay(0x4C4B40 = 5 000 000)
```

`0x5006A7DC` — busy-wait по `0x50015B40` (таймер) до `w20`; `0x4C4B40` = 5 000 000 →
**5.000 s** (единица — мкс, если тик 1 МГц; иного смысла у 0x4C4B40 нет).
`0x50054010` → `b 0x500557C0` — блок `verify boot fail, it will power off!`.

### 3.2 Сеттер `0x50053F6C` — проверка утверждения STATUS §19.2

```asm
0x50053f6c  adrp x8, 0x500c4000
0x50053f70  str  w0, [x8, 0xfa8]     ; *(int*)0x500C4FA8 = arg; ret
```

Это **тупой сеттер без логики**. Три вызова (BL, полный скан payload):

| # | адрес вызова | что записывается |
|---|---|---|
| 1 | `0x50053910` | `w0 = 2` если `img_auth_required==0` (`0x500538E4`), иначе `w0 = 3` (`0x5005390C`) |
| 2 | `0x50053AD4` | `w0 = 2`, если `sec_cfg_get_lock_state()` вернул 0 **и** `lock_state == 3` |
| 3 | `0x50053CC8` | `w0 = 0` (green) на успешной верификации |

```asm
0x50053ab4  add  x0, sp, 0x14
0x50053ab8  bl   0x500326ac          ; sec_cfg_get_lock_state(&ls)  (thunk -> 0x50082AE0)
0x50053abc  mov  w20, w0
0x50053ac0  cbnz w0, 0x50053ad8      ; ошибка чтения seccfg -> НЕ пишем orange
0x50053ac4  ldr  w8, [sp, 0x14]
0x50053ac8  cmp  w8, 3
0x50053acc  b.ne 0x50053ad8
0x50053ad0  mov  w0, 2
0x50053ad4  bl   0x50053f6c          ; boot_state = ORANGE
0x50053ad8  bl   0x50053f38          ; (пустой ret-заглушка, 0x50053F38 = ret)
0x50053adc  ...                       ; выбор строки "boot"/"recovery" для баннера
0x50053af0  bl   0x50053f78          ; banner
0x50053b14  bl   0x50053f3c          ; запись androidboot.verifiedbootstate=<color>
```

**Уточнение к формулировке STATUS §19.2.** По адресам третий вызов — `0x50053CC8`
(green), но по **порядку исполнения** он не последний: `0x50053CC8` делает
`b 0x50053A88` → `0x50053AA4` → `0x50053AB4` → `0x50053AD4`. Т.е. последовательность
исполнения: `green` (если AVB прошёл) → затем **orange поверх**, если `lock_state==3`.
Поэтому «последняя запись lock==3 → 2» — **верно**, но обоснование в STATUS неполное
(дело не в порядке адресов).

### 3.3 Что именно «AVB прошёл» в этой функции

Функция `0x50053848` верифицирует **не boot, а vendor_boot**:

```asm
0x50053968  adrp x24, 0x5008f000 ; add x24,x24,0xe6d   ; x24 = 0x5008FE6D = "vendor_boot"
0x50053974  add  x2, x2, 0x48c                          ; "%s%s"
0x5005397c  mov  x3, x24
0x50053980  mov  x4, x26                                ; x26 = suffix ("a"/"b"/"")
0x50053984  bl   0x5006b374                             ; snprintf(buf,"%s%s","vendor_boot",suffix)
0x500539a0  bl   0x50069b84                             ; partition lookup
```

При неудаче — `0x500AC4AA "partition vendor boot not exists\n"` (`0x50053A04`),
при успехе — `0x500AC4CC "vendor_boot exists\n"` (`0x50053A2C`).
Далее `0x50087234` — MTK-обёртка над `avb_slot_verify` (6 аргументов:
`x0`=ops, `x1`=список разделов, `x2`=suffix, `w3`=flags, `w4`=verify-mode, `x5`=out;
пролог `0x50087254 stp`/`0x5008725c mov w26,w3`, проверки `cmp w25,3/4` и `tbz w26,2`):

```asm
0x50053b50  bl   0x5001def8        ; suffix
0x50053b68  mov  w3, w23           ; flags = w28 | (dm_verity? 2:0)
0x50053b6c  bl   0x50087234
```

где `w28 = 1` ровно когда `img_auth_required == 0` (`0x500538E0`), см. §4.

**Следствие (важное для всего разбора):** модифицированный **boot**-рамдиск эту
проверку не ломает — LK здесь boot не верифицирует. Поэтому v5 и загрузился.
Из этого же следует, что состояние после успешной проверки стокового vendor_boot —
**green (0)**, и остаётся green, если `lock_state != 3` (или чтение seccfg упало).

### 3.4 `oplusboot.verifiedbootstate=`

Второй аппендер — в `boot_linux`:

```asm
0x5000d468  bl   0x50053f60                  ; get_boot_state()
0x5000d46c  cmp  w0, 3
0x5000d470  b.hi 0x5000d484
0x5000d474  adrp x8, 0x50094000 ; add x8,x8,0x8f8
0x5000d47c  ldr  x0, [x8, w0, sxtw 3]        ; таблица 4 указателей
0x5000d480  bl   0x50018204                  ; cmdline_append
```

Строки `oplusboot.verifiedbootstate=orange/yellow/red/green` лежат по
`0x5009283F / 0x50092862 / 0x50092885 / 0x500928A5`. Таблица `0x5009408F8` — в .bss
(0x9408F8 > размера payload 0xE4600), заполняется в рантайме; **прямых `adrp+add` на эти
четыре литерала в payload нет** (полный скан ADRP+ADD: ни одного xref), поэтому
конкретный populator я не локализовал — это место отмечаю как непроверенное.
Для гейта в `SecondStageMain` это несущественно: `fs_mgr_get_boot_config("verifiedbootstate")`
читает `androidboot.verifiedbootstate` из bootconfig/`ro.boot.*`, а не `oplusboot.*`.

### 3.5 Вердикт Q2

* `2 == orange` — **да**, таблица `0x500AC700[2] = 0x500AC5D6`.
* `lock_state==3 ⇒ orange` — **да**, `0x50053ACC`/`0x50053AD4`.
* Путь активен в реальном boot: `0x50053848` вызывается из
  `boot_linux_from_storage` безусловно (`0x5000D9F4` — тип 1 recovery,
  `0x5000DA24` — тип 0 boot); `buildvariant=user` — это лишь токен cmdline из
  vendor_boot-хедера (`0x5009206B "…nt=user"`), ветвлений по нему в LK нет.
* **STATUS §19.2 верен по коду.** Значит либо `lock_state` в момент загрузки LK
  **не равен 3** (см. errata `re-lk-seccfg.md`: при ошибке валидации геттер
  fail-safe отдаёт `1`, а не 0), либо orange выставляется, но по какой-то иной
  причине не доезжает до второй стадии. Первое — гораздо вероятнее и полностью
  объясняет наблюдаемое `unauthorized`. Проверяемо только чтением seccfg.

---

## 4. Q3 — `img_auth_required` и толерантность AVB

### 4.1 Ключ — `(sboot_state, lock_state)`

`0x50032658` (thunk) → `0x50076B18` → `0x50076BF8`:

```asm
0x50076c18  bl   0x5007ef04              ; sboot_state -> w0
0x50076c1c  cbz  w0, 0x50076c30
0x50076c20  ...  "[SEC] get sboot state fail, ret: %d"      ; 0x500B74F6
0x50076c30  add  x0, sp, 8
0x50076c34  bl   0x500326ac              ; sec_cfg_get_lock_state(&ls)
0x50076c38  cbz  w0, 0x50076c7c
0x50076c3c  ...  "[SEC] part_name invalid..." / fail -> 1
0x50076c7c  ldur w9, [x29, -4]           ; w9 = sboot
0x50076c80  ldr  w8, [sp, 8]             ; w8 = lock_state
```

Четыре ветки, каждая — `ldrb w20, [&table[index*0x30] + off]`:

| sboot_state | lock_state | смещение в записи | инструкция |
|---|---|---|---|
| 0 | 3 | `+0x24` | `0x50076CA0` |
| 0 | != 3 | `+0x20` | `0x50076CC4` |
| 1 | 3 | `+0x2c` | `0x50076CEC` |
| 1 | != 3 | `+0x28` | `0x50076D18` |

Индекс — результат поиска имени (`0x50076B40`, 23 записи по 0x30, имя = одно из
4 указателей на запись; при промахе — `"[SEC_POLICY] part_name invalid, use default policy"`
`0x500B7482` и индекс 0).

**Ключ тот же, что у boot-state: `(sboot_state, lock_state)`.** Никакого отдельного
«списка допустимых ошибок AVB» нет — «толерантность» это один байт политики на
пару (состояние загрузки, состояние блокировки).

### 4.2 Чего я не смог прочитать статически

Таблица `0x500EDDC8` (23 × 0x30) — **в .bss** (payload кончается на `0x500E4600`),
в файле её нет. Все обращения к ней — только чтения (`0x50076C90/CB4/CDC/D08`);
populator, который её заполняет, по прямой ссылке `adrp+add` не находится
(адрес, вероятно, передаётся в `memcpy` как параметр). Поэтому **значения
`boot+0x24 = 2` из STATUS §19.2 я подтвердить не могу** — их в бинаре нет.
Это отдельно отмечаю как расхождение с STATUS.

### 4.3 Покрывает ли толерантность `vendor_boot`?

Да, и по неочевидной причине: **флаги для `avb_slot_verify(vendor_boot)` берутся из
строки `"boot"`/`"recovery"`**, а не из строки vendor_boot.

```asm
0x500538c4  bl   0x50032658             ; x0 = "boot" | "recovery"
0x500538dc  cbnz w21, 0x50053908       ; img_auth_required != 0 -> state=3
0x500538e0  mov  w28, 1                ; бит толерантности
0x500538e4  mov  w0, 2                 ; и заодно state = ORANGE
...
0x50053a40  bl   0x5005360c             ; get_dm_verity_status
0x50053a4c  orr  w9, w28, 2
0x50053a58  csel w23, w28, w9, eq       ; flags = tolerant | (verity?2:0)
0x50053a70  bl   0x5008d1d8             ; сравнение digest vbmeta
0x50053b6c  bl   0x50087234             ; avb_slot_verify(..., flags=w23, ...)
```

Отдельной записи политики для `vendor_boot` в этом пути **нет** — значит:

* если политика для boot толерантна (`img_auth_required==0`), то и патченый
  `vendor_boot` будет принят (и, заметьте, LK тут же поставит `state=2/orange`);
* если нетолерантна — `avb_slot_verify` вернёт hash-mismatch, зелёный не выставится,
  и останется `3 (red)` → баннер → `power off`.

Второй, независимый источник толерантности — бит `VERIFICATION_DISABLED` в vbmeta:
`0x50053C88 bl 0x5008ae80` → `0x50053C8C tbz` → `0x50053C90 ldurb` → `0x50053C94 cbnz`
(при установленном бите уходим на `0x50053CF4`, где собираются
`androidboot.vbmeta.hash_alg` / `.size` / `.digest`, строки `0x500AC588/5A4/5BC`).
Если чтение бита падает — `0x500AC543 "[AVB] Fail To Get Verification Disabled Bit"`.

**Практический вывод:** флеш патченого vendor_boot сам по себе **не** более опасен,
чем уже прошитый патченый boot: оба проходят через один и тот же флаг. Но он и не
даёт ничего (см. §2.6 — vendor-рамдиск в rootfs проигрывает), а ломает
`vendor_boot`-хедер/смещения и vbmeta-цепочку. Отдельный риск: если политика вдруг
нетолерантна именно к vendor_boot (чего я доказать не могу из-за .bss-таблицы),
получим red → power off вместо загрузки.

---

## 5. Q4 — предсказание для v6

### 5.1 Что v6 делает и чего не делает

v6 по контракту: P1 (`boot /init` `0x2F6D14`), P2 (`vendor system/bin/init` `0xF1710`),
плюс `/force_debuggable` и `/adb_debug.prop` в оба рамдиска.

* P1 снимает зависимость `setenv("INIT_FORCE_DEBUGGABLE","true")` от копии
  `/userdebug_plat_sepolicy.cil` (`0x2F6D14`, см. `re-init-prop-gate.md` §2).
* P2 делает то же самое в vendor-сборке (`0xF1710`) — на случай, если бы выиграл
  vendor `/init`.
* Маркеры `/force_debuggable` + `/adb_debug.prop` нужны first stage, чтобы
  скопировать prop в `/debug_ramdisk/adb_debug.prop`.

**Ни один из трёх пунктов не влияет на второй гейт** в `SecondStageMain`:
`getenv("INIT_FORCE_DEBUGGABLE")=="true" && AvbHandle::IsDeviceUnlocked()`,
где `IsDeviceUnlocked() ⇔ verifiedbootstate=="orange"` (`re-init-prop-gate.md` §3).
Если orange нет — `UmountDebugRamdisk()` выполняется **до** `PropertyInit()`,
`/debug_ramdisk/adb_debug.prop` не виден, `ro.adb.secure` остаётся 1 → `unauthorized`.

**Предсказание: `unauthorized` (не `device`).** Единственный сценарий, где v6 даст
`device` — если `verifiedbootstate` уже orange (тогда хватило бы и v5, и v6 просто
ничего не сломает).

### 5.2 Проверка согласованности с наблюдениями

| наблюдение | объяснение по этому разбору |
|---|---|
| v5 загрузился (не power-off) | LK верифицирует только vendor_boot (§3.3); он сток → green |
| `ro.adb.secure` остался 1 | green ⇒ `/debug_ramdisk` размонтирован до `PropertyInit` |
| `adb unauthorized` | adbd поднялся, `ro.adb.secure=1`, ключа в `/data/misc/adb` нет |
| нет 5-секундной паузы (если её нет) | green, а не orange |

Т.е. **наблюдения согласуются с «green», а не с «orange»**, и это ровно то, что
предсказывает код при `lock_state != 3` (или при провале чтения seccfg, который
fail-safe даёт `1`).

### 5.3 Единственное наблюдение, доказывающее отсутствие orange

Ограничения: экран мёртв, `adb` не авторизован (шелла нет), DA доступен только в
preloader-режиме, expdb пуст. Свойства прочитать нечем.

**Наблюдение: длительность «мёртвого» интервала между исчезновением preloader/LK
USB-устройства и появлением USB-интерфейса adbd.**

Код orange-ветки делает `mdelay(0x4C4B40)` = **5 000 000 мкс = ровно 5.000 s**
(`0x50053FF4`–`0x50053FFC`), причём **после** баннера и **до** прыжка в ядро.
Никакая другая ветка (green) пауз не делает; yellow/red вообще уводят в power-off.

Методика: `date +%s.%N` в момент подачи питания (или в момент пропадания
preloader-порта из `lsusb`-эквивалента `/sys/bus/usb/devices`) и в момент первого
появления `adb`-интерфейса; сравнить с заведомо green-загрузкой того же образа
(любая сток-прошивка с залоченным seccfg).

* Δ отличается на **≈5.0 s** → orange присутствует, гейт в `SecondStageMain` проходит,
  и причина `unauthorized` — другая (искать в first/second stage).
* Δ такой же, как у green (**паузы нет**) → **orange отсутствует**, доказано:
  `0x50053AD4` — единственное место, где orange ставится по lock_state, а
  `0x50053F54` — единственное, где он попадает в cmdline.

Запасной (более прямой, но требующий preloader-чтения): дамп `seccfg` и проверка,
что main-запись `MMMM` проходит валидацию LK (`SHA256(hdr)` + HACC, `0x500827E8`)
и `+0xC == 3`. Если запись невалидна — LK fail-safe отдаёт `lock_state = 1`
(`re-lk-seccfg.md`, errata), orange не пишется, и это тоже доказывает его отсутствие.
Оба наблюдения взаимоисключающих исходов не имеют, но первое не требует
пересчёта HACC.

---

## 6. Confidence и falsifiers (сводно)

| утверждение | confidence | что его опровергнет |
|---|---|---|
| база LK = 0x50000000 | высокая (4/4 литерала) | — |
| `[vendor][boot]` вплотную, без padding | высокая (два `memcpy` подряд с `add x19,x8,w0`) | если ядро печатает `junk in compressed archive` — значит второй архив не распаковался |
| `initrd-start = 0x66F00000` | высокая (start+total+bootconfig = адрес записи bootconfig) | `cat /proc/device-tree/chosen/linux,initrd-start` != 0x66F00000 |
| bootconfig сразу за рамдисками, ≤0x800 B | высокая | — |
| `/init` = boot-рамдиск (Q1 false) | высокая | `ls -l /init` даёт симлинк |
| enum 0/1/2/3 = green/yellow/orange/red | высокая (таблица + баннер) | — |
| `lock_state==3 ⇒ orange` в коде | высокая | — |
| orange реально выставляется на этом устройстве | **средняя** (зависит от валидности seccfg в рантайме) | 5-секундная пауза отсутствует |
| `img_auth_required` = байт политики по `(sboot,lock)` | высокая | — |
| значения таблицы политики (`boot+0x24 == 2`) | **не подтверждено** (таблица в .bss) | дамп RAM LK на устройстве |
| vendor_boot верифицируется флагами строки "boot" | высокая | — |

---

## 7. Рекомендация (одна строка)

**Патченый `vendor_boot` не флешить: он не может выиграть overlay и не снимает гейт
`verifiedbootstate=="orange"`, а добавляет риск red-state → power-off; сначала измерить
orange (5-секундная пауза) и при его отсутствии чинить `lock_state`/cmdline, а не рамдиски.**

---

## 8. Правки к другим документам

1. `PLAN-q1-q2-2026-10-25.md` §E и задание: load base — **0x50000000**, не 0x40000000.
2. `STATUS-rmx3630-2026-10-24.md` §19.2: «последняя запись lock==3→2» — верно, но
   порядок в бинаре другой (`0x50053CC8` green стоит по адресу позже, а исполняется
   раньше); объяснение «red остаётся только если чтение seccfg падает» —
   **неверно**: red транзиентен и перекрывается green на успешной верификации
   (`0x50053CC8`), а orange — только при `lock_state==3`.
3. Там же: «в таблице для boot `+0x24 (lock==3) = 2` → 0» — значения таблицы
   `0x500EDDC8` в бинаре нет (bss), утверждение недоказуемо статически.
4. `re-init-prop-gate.md` §3: гейт описан верно, но он **достижим** — LK действительно
   ставит orange при `lock_state==3`; вопрос только в том, равен ли `lock_state` трём
   **после** валидации seccfg в LK.
5. Новое: LK в этом Boot-пути верифицирует **vendor_boot**, а не boot
   (`0x50053968`…`0x50053B6C`) — это объясняет, почему патченый boot загружается.

---

## 9. Логи (воспроизведение)

Полный лог: `/tmp/opencode/lk_ev.log` (скрипт `/tmp/opencode/lk_ev.sh`), **exit 0**.

```
$ bash /tmp/opencode/lk_ev.sh > /tmp/opencode/lk_ev.log 2>&1 ; echo EXIT=$?
EXIT=0
```

### 9.1 r2: сеттер/геттер/баннер

```
$ r2 -q -e scr.color=0 -a arm -b 64 -m 0x50000000 -c 's 0x50053f3c; pd 12' lk_payload.bin
        :   0x50053f3c      880300b0       adrp x8, 0x500c4000
        :   0x50053f40      08a98fb9       ldrsw x8, [x8, 0xfa8]
        :   0x50053f44      1f0d0071       cmp w8, 3
       ,==< 0x50053f48      a8000054       b.hi 0x50053f5c
       |:   0x50053f4c      c90200b0       adrp x9, 0x500ac000
       |:   0x50053f50      29011c91       add x9, x9, 0x700
       |:   0x50053f54      207968f8       ldr x0, [x9, x8, lsl 3]
       |`=< 0x50053f58      ab10ff17       b 0x50018204
       `--> 0x50053f5c      c0035fd6       ret
            0x50053f60      880300b0       adrp x8, 0x500c4000
            0x50053f64      00a94fb9       ldr w0, [x8, 0xfa8]
            0x50053f68      c0035fd6       ret
            0x50053f6c      880300b0       adrp x8, 0x500c4000
            0x50053f70      00a90fb9       str w0, [x8, 0xfa8]
            0x50053f74      c0035fd6       ret
            0x50053f78      fd7bbfa9       stp x29, x30, [sp, -0x10]!
```

### 9.2 r2 + objdump: lock_state → orange

```
$ r2 -q -e scr.color=0 -a arm -b 64 -m 0x50000000 -c 's 0x50053aa4; pd 15' lk_payload.bin
            0x50053ab4      e0530091       add x0, sp, 0x14
            0x50053ab8      fd7aff97       bl 0x500326ac
            0x50053abc      f403002a       mov w20, w0
        ,=< 0x50053ac0      c0000035       cbnz w0, 0x50053ad8
        |   0x50053ac4      e81740b9       ldr w8, [sp, 0x14]
        |   0x50053ac8      1f0d0071       cmp w8, 3
       ,==< 0x50053acc      61000054       b.ne 0x50053ad8
       ||   0x50053ad0      40008052       mov w0, 2
       ||   0x50053ad4      26010094       bl 0x50053f6c

$ aarch64-linux-gnu-objdump -D -b binary -m aarch64 --adjust-vma=0x50000000 \
      --start-address=0x50053ab4 --stop-address=0x50053ad8 lk_payload.bin
    50053ab4:	910053e0 	add	x0, sp, #0x14
    50053ab8:	97ff7afd 	bl	0x500326ac
    50053abc:	2a0003f4 	mov	w20, w0
    50053ac0:	350000c0 	cbnz	w0, 0x50053ad8
    50053ac4:	b94017e8 	ldr	w8, [sp, #20]
    50053ac8:	71000d1f 	cmp	w8, #0x3
    50053acc:	54000061 	b.ne	0x50053ad8  // b.any
    50053ad0: 52800040 	mov	w0, #0x2                   	// #2
    50053ad4: 94000126 	bl	0x50053f6c
```

### 9.3 objdump: два memcpy сборки initrd

```
$ aarch64-linux-gnu-objdump -D -b binary -m aarch64 --adjust-vma=0x50000000 \
      --start-address=0x5000ddb8 --stop-address=0x5000de00 lk_payload.bin
    5000ddb8:	97fff230 	bl	0x5000a678
    5000ddbc:	aa0003f8 	mov	x24, x0
    5000ddc0:	97fff278 	bl	0x5000a7a0
    5000ddc4:	2a0003e2 	mov	w2, w0
    5000ddc8:	aa1303e0 	mov	x0, x19
    5000ddcc:	aa1803e1 	mov	x1, x24
    5000ddd0:	94017afe 	bl	0x5006c9c8
    5000ddd4:	97fff273 	bl	0x5000a7a0
    5000ddd8:	f9403fe8 	ldr	x8, [sp, #120]
    5000dddc:	8b204113 	add	x19, x8, w0, uxtw
    5000dde0:	f9003ff3 	str	x19, [sp, #120]
    5000dde4:	97fff1f6 	bl	0x5000a5bc
    5000dde8:	aa0003f8 	mov	x24, x0
    5000ddec:	97fff24a 	bl	0x5000a714
    5000ddf0:	2a0003e2 	mov	w2, w0
    5000ddf4:	aa1303e0 	mov	x0, x19
    5000ddf8:	aa1803e1 	mov	x1, x24
    5000ddfc:	94017af3 	bl	0x5006c9c8
```

### 9.4 callers (полный скан B/BL по payload)

```
### 3. callers of set_boot_state 0x50053f6c
  caller 0x50053910 (BL)
  caller 0x50053ad4 (BL)
  caller 0x50053cc8 (BL)

### 7. callers of the boot-state/AVB function 0x50053848
  caller 0x5000d9f4 (BL)
  caller 0x5000da24 (BL)
```

### 9.5 размеры и арифметика

```
### 11. size getters
0x5000a7a0  adrp x8,0x50113000 ; add x8,x8,0x9e8 ; ldr w0,[x8]      ; vendor_hdr+0x18
0x5000a714  ... boot_hdr+0x0C (hv>2)                                 ; boot ramdisk_size
0x5000a55c  ... add x10,x10,0x9e4 ; ldr w0,[x8]                      ; vendor_hdr+0x14 = 0x66F00000
0x5000a910  ... [x9]=vendor_hdr+0x18 ; w9 = w9 + w10 ; csel w0,w9,w8,hi

### 15. arithmetic for the stock pair
  vendor_ramdisk_size = 35835345 = 0x222cdd1
  boot  ramdisk_size  = 1649781 = 0x192c75
  total               = 37485126 = 0x23bfa46
  vendor @ 0x66F00000 .. 0x6912cdd1
  boot   @ 0x6912cdd1 .. 0x692bfa46
  bootconfig @ 0x692bfa46
```

### 9.6 строки (адрес → текст)

```
0x50092073 | 'linux,initrd-start'
0x5009208f | 'linux,initrd-end'
0x5009227c | '%s:%d: ramdisk_addr (0x%x) is not taken from mb (0x%llx)\n'
0x50092259 | 'boot_linux_from_storage'
0x50092215 | '%s:%d: ramdisk_map_sz (0x%x) cannot overrun LK_RAMDISK_SIZE (0x%x)\n'
0x5008fe6d | 'vendor_boot'
0x5008f48c | '%s%s'
0x500ac44d | '[AVB] invalid boot image type'
0x500ac46c | '[AVB] img_auth_required = %d'
0x500ac4aa | 'partition vendor boot not exists'
0x500ac4cc | 'vendor_boot exists'
0x500ac51b | 'root=/dev/ram'
0x500ac543 | '[AVB] Fail To Get Verification Disabled Bit'
0x500ac666 | 'Orange State\n\n'
0x500b7482 | '[SEC_POLICY] part_name invalid, use default policy'
0x500b74f6 | '[SEC] get sboot state fail, ret: %d'
```
