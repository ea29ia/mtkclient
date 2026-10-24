# RE: корневая причина silent-skip — stub 0x4002F804 (наш собственный патч)

Дата: 2026-10-24. Бинарь: `/home/musin/firmware/extracted/IMAGES/da2_oplus.bin`.

## TL;DR

Патч, зарегистрированный в `xml_lib.apply_oplus_runtime_patches` как
«oplus image hash-list check 0x4002f804 -> MOV R0,#0; BX LR», на самом деле
заменял **диспетчер записи consumer'а** — функцию `0x4002F804`, которая:

```
push {r4,r5,r6,r7,r8,sb,sl,fp,lr}
r4 = buf; sl = len; sb = &ctx1; r6 = &0x4006E7C8 (sparse flag)
r8 = policy[+1] | policy[+2]        (hash_binding | img_auth)  <- F1 патчит в 0
bl 0x4002E4B0                       (is_sparse)                <- F3 патчит в 0
strb r0,[r6]
beq 0x4002F92C -> 0x4002F984
  bl 0x4002D5A8 (bulk init: LBA/len/region, h+0x34 = region list)
  ... 0x4002FE4C: cmp sl,#0
       sl>0  -> bl 0x4002D66C(handle, buf, len)  <- РЕАЛЬНАЯ ЗАПИСЬ
       sl==0 -> ensure-init + chunk=0
```

Stub `mov r0,#0; bx lr` ⇒ каждый чанк «успешно» обрабатывается без
инициализации хэндла и без записи. Это в точности объясняет все
наблюдения:

| Наблюдение | Объяснение через stub |
|---|---|
| F5-маркер `0x4006E7C8` = 0 | stub возвращается до `strb`/записи маркера |
| bulk handle `0x4006E790` — все нули | `0x4002D5A8` никогда не вызван |
| F1/F3 применялись, но ни на что не влияли | код до них не доходил |
| `ctx2+0xE0/E4` = 0, `Download_data end.` | stub вернул 0 — «успех» |
| приём 0x80000/0x800000 полный, target==received | producer здоров, consumer «съел» чанки no-op'ом |
| флеш не менялся ни для para, ни для seccfg | глобально, не зависит от раздела |
| readback/чтения работают | read-движок (0x400309a4...) — другая функция |

## Фикс

Патч вынесен за флаг `OPLUS_PATCH_F804_STUB=1` (**по умолчанию OFF**).
Настоящие хэш-гейты по-прежнему закрыты F1 (`0x4002F850 -> mov r8,#0`)
и патчем entity-compare `0x4002FCF4`.

Ожидаемое поведение после фикса (live-верификация):
- F5-маркер `0x4006E7C8` = длина чанка (ненулевая);
- `0x4006E790+0x34` != 0 (region list построен);
- para: паттерн **COMMITTED**;
- затем seccfg: lock=3 записан, readback подтверждает.
