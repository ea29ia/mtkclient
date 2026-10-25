# Runbook: RMX3630 campaign, хост = рутованный Android + OTG (без ПК)

Дата: 2026-10-24. Заменяет PC-based окружение. Актуальный handoff: `HANDOFF-2026-10-25.md`.
Проверено: proot Debian в Termux (aarch64) — реверс-инструменты работают (r2, objdump),
но **USB из proot недоступен** (fake root, /dev/bus/usb EACCES, proot-su фейковый).
Вывод: mtkclient запускается в **Termux native**; proot остаётся для статики/реверса.

## 1. Установка окружения (Termux native, не proot)

```sh
pkg update
pkg install python git libusb libudev-zero clang binutils
git clone -b oplus-mt6789-unlock https://github.com/ea29ia/mtkclient.git ~/mtkclient
cd ~/mtkclient
pip install -r requirements.txt
```

Если pip падает на capstone/keystone — собрать из исходников (в termux есть clang);
это нужно только для офлайн-патчей, для runtime patch_mem не критично.

## 2. Root + SELinux (реальный su из Termux, НЕ внутри proot)

```sh
su -c "setenforce 0"        # иначе SELinux убивает raw usb access libusb
su -c "chmod -R 666 /dev/bus/usb"   # или запускать сам mtk под su
```

Проверка реального root: `su -c id` в **Termux-сессии** должен показать
`uid=0(root) ... context=u:r:magisk:s0` (или подобный). Внутри proot тот же вывод
будет с proot-контекстом — это подделка, USB так не заработает.

## 3. Подключение

1. OTG-переходник: хост-телефон -> цель (RMX3630).
2. Цель: 3-кнопочный комбо при подключении USB (проверенный метод для dead-screen,
   ~12 с на поимку окна; preloader окно ~150-250 мс — mtkclient успевает).
3. Android может поднять диалог "заряжается/передача файлов" на ЦЕЛИ — не важно,
   preloader VCOM (22d9:0006) отделяется кнопками.

## 4. Что на Android НЕ нужно (из PC-runbook)

- udev rules (99-mtk-noaudio.rules) — заменяются unbind-циклом в скрипте ниже.
- ModemManager — отсутствует на Android.
- Отдельный venv — не обязателен.

## 5. Запуск

```sh
cd ~/mtkclient
bash docs/notes/run_mtk_dabr_loop_android.sh
```

Скрипт: ждёт 22d9:0006, unbind'ит cdc_acm/snd-usb-audio, удаляет .state/hwparam.json,
запускает `mtk.py da seccfg unlock` (env = финальная конфигурация «Прорыва 22:00-22:35»),
логи в ~/mtk_logs/attempt_N.log. Для чтения: заменить команду на `mtk.py r seccfg ...`.

## 6. Порядок операций с seccfg (КРИТИЧНО — из session doc)

1. `w seccfg backup` (WRITE-PARTITION путём) -> 2. `r seccfg` != zeros ->
3. `da seccfg unlock` -> 4. `r seccfg` lock_state=3 -> 5. `da reset`.

ЗАПРЕЩЕНО: WRITE-FLASH (`w`/`wo`/`wf`) на seccfg — anti-tamper зануляет область
(4 подтверждения; см. re-writeflash-scrubber.md: это безусловный erase @0x4000325c).

## 7. Новые патчи из реверса 2026-10-24 (до применения на устройстве)

См. re-*.md отчёты. Кандидаты (patch_mem через heapbait):
- `0x4000325c: blx r2 -> mov r0,#0` — убить erase WRITE-FLASH (валидировать на
  НЕ-seccfg разделе!); снимает вопрос скруббера, но WRITE-FLASH всё равно избегаем.
- `0x40034f94: beq 0x40034ffc` форс — принять main-рекорд без hash-проверки
  (вопрос доверия LK открыт — см. переписку; сначала маркерный тест rewrite-vs-view).
- HACC busy-wait NOPs: `0x40039848`, `0x400397e0`, `0x40034b18` — кандидат на причину
  post-write hang. Сначала диагностика: READ-REGISTER 0x1000A008 во время зависания.

## 8. Известные подводные камни на Android-хосте (новые, проверять)

- **USB timing**: Android-ядро может медленнее поллить события; окно preloader 150-250 мс
  — если mtkclient не ловит, стараться запускать цикл ДО подключения цели.
- **OTG power**: некоторые телефоны рвут шину при просадке; использовать короткий кабель.
- **Sleep/doze**: держать экран хоста включённым (`termux-wake-lock`), иначе ядро
  suspend'ит USB-хост посреди XML-сессии -> instant EIO (кандидат на «случайные» смерти).
- **selinux после перезагрузки** вернётся в enforcing — повторять setenforce 0.
