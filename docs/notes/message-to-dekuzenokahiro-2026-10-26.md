Привет!

Мы закончили офлайн-работу по DA1 на MT6789 (RMX3630) и нашли то же самое
семейство уязвимостей в старой сборке DA1 **C.25** — то есть в том блобе
`MTK6789_REALME.bin` (sha256 `024d01b8...`), который ты раньше выкладывал.
Спасибо за него — она оказалась ключевой.

## Что мы сделали

1. Статический аудит C.25 DA1: команда `CMD:DEBUG:DRAM-REPAIR`
   зарегистрирована, tripwire-патча нет, приём длины от хоста не ограничен —
   то есть уязвимость HeapBait (bkerler/mtkclient PR #414) жива в C.25.
2. Порт нашей цепочки в эмуляторе Unicorn: staging по фиксированному адресу
   0x40000000 через проваливающийся BOOT-TO -> переполнение в DRAM-REPAIR
   (declared length 0x3C) -> исполнение 76-байтового стаба -> запись
   sha256(патченного DA2) в слот DA1 -> DA1 остаётся живой -> настоящий
   BOOT-TO принимает патченный DA2. Всё детерминированно (5/5 прогонов).
3. Проверили подпись: твой контейнер подписан тем же ключом (K1), что и
   наша сборка 200EX01, поэтому твой preloader примет и наш подписанный DA1.

## Просьба: прогнать команды и прислать логи

Готов раннер: `docs/notes/da1_c25_run.py` и ранбук
`docs/notes/reverse/re-da1-c25-runbook-2026-10-26.md` (ветка
`oplus-mt6789-unlock` в https://github.com/ea29ia/mtkclient).

Важно: НИЧЕГО из этого не пишет во flash/seccfg/RPMB. Худшее, что может
случиться — DA1 упадёт, это лечится переподключением к preloader (шаг 5).
Устройство НЕ рутуется и НЕ перепрошивается этим скриптом.

Установка:
  pkg install python git libusb libudev-zero clang binutils   # Android-хост
  # на Linux-PC: git clone + pip install pyusb capstone unicorn mock serial pycryptodome colorama
  pip install pyusb capstone unicorn mock serial pycryptodome colorama

Без телефона:
  python docs/notes/da1_c25_run.py --mode check --container <путь к mt6789_realme.bin>
  python docs/notes/da1_c25_run.py --mode verify-offline --container <путь>
  Оба должны закончиться PASS. Пришли весь вывод.

С телефоном, по одному шагу (шаги 2-4 сразу после шага 1, в той же сессии):
  python docs/notes/da1_c25_run.py --mode device --step 1 --dry-run
  python docs/notes/da1_c25_run.py --mode device --step 1   # attach + загрузка DA1
  python docs/notes/da1_c25_run.py --mode device --step 2   # staging (fail BOOT-TO)
  python docs/notes/da1_c25_run.py --mode device --step 3   # fire (DRAM-REPAIR L=0x3C)
  python docs/notes/da1_c25_run.py --mode device --step 4   # BOOT-TO с патченным DA2
  (шаг 5 — восстановление: переподключение + перезаливка DA1)

Телефон подключать, удерживая Vol Up + Vol Down + Power (окно preloader
~150-250 мс, запускай команду ДО подключения). На Linux-PC команды с sudo.

Что прислать обратно: ПОЛНЫЙ stdout каждого шага (особенно строки
probe / BOOT-TO response / DA verdict / DRAM-REPAIR response) и все строки
с [!]/[-]/ошибками mtkclient. Успех шага 4 выглядит как
  SUCCESS: DA1's own hash gate PASSED (rc=0) with the patched DA2.
Если что-то умерло — не страшно: шаг 5, и заново со шага 2.

Вопросы по шагам — пиши, ранбук короткий и конкретный.
