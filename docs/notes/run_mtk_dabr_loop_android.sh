#!/system/bin/sh
# run_mtk_dabr_loop_android.sh — адаптация run_mtk_dabr_loop.sh под Android/Termux (root)
# Хост: рутованный Android-телефон (Termux native, НЕ proot), цель: RMX3630 (22d9:0006) через OTG.
# Отличия от Linux-версии:
#  - нет udev: unbind cdc_acm/snd-usb-audio делаем сами из sysfs по root
#  - ModemManager отсутствует на Android (одна проблема меньше)
#  - SELinux: нужно setenforce 0 перед стартом (libusb raw access)
#  - .state/hwparam.json удаляются перед каждой попыткой (как на ПК)

PREFIX=/data/data/com.termux/files/usr
MTKDIR=$HOME/mtkclient
VIDPID="22d9:0006"
LOGDIR=$HOME/mtk_logs
mkdir -p "$LOGDIR"

# --- env (финальная рабочая конфигурация, см. session doc "Прорыв 22:00-22:35") ---
export OPLUS_PATCH_LEVEL=5      # bare RET0 + прямой patch_mem g_oplus_auth_status=1
export OPLUS_SKIP_SLA=0         # SLA dance ОБЯЗАТЕЛЕН (иначе GET-HW-INFO hang)
export OPLUS_SKIP_HWINFO=1      # первый post-SLA transfer всегда EIO — host ничего не трогает
export OPLUS_NO_DRAIN=1
export OPLUS_LEGACY_HOST=1      # без retry/flush — они убивали сессию
export OPLUS_STORAGE=ufs
export OPLUS_HWINFO_LATE=1
export OPLUS_SBC_PATCH=0        # патч get_hw_sbc = смерть сессии
export OPLUS_WRITE_BYPASS=1     # deny-check + state-writers MOV r1,#3
export OPLUS_FLUSH=1            # reactive flush на границах команд

n=0
while true; do
    n=$((n+1))
    LOG="$LOGDIR/attempt_$n.log"
    echo "[attempt $n] waiting for $VIDPID ..."

    # Ждём появления preloader VCOM
    found=""
    for i in $(seq 1 100); do
        if lsusb 2>/dev/null | grep -q "$VIDPID"; then found=1; break; fi
        # fallback без lsusb: скан /dev/bus/usb
        if [ -z "$found" ] && su -c "grep -l . /dev/bus/usb/*/* 2>/dev/null" >/dev/null 2>&1; then :; fi
        sleep 0.2
    done
    [ -z "$found" ] && continue

    # Android-аналог udev-правил: отвязать kernel-драйверы от интерфейсов OPLUS
    # (cdc_acm захватывает bulk-интерфейсы и блокирует libusb)
    su -c '
    for d in /sys/bus/usb/drivers/cdc_acm/*:*; do
        case "$d" in *:*) echo "$d" | grep -q "22d9" && echo "$d" > /sys/bus/usb/drivers/cdc_acm/unbind 2>/dev/null;; esac
    done
    for d in /sys/bus/usb/drivers/snd-usb-audio/*:*; do
        case "$d" in *:*) echo "$d" > /sys/bus/usb/drivers/snd-usb-audio/unbind 2>/dev/null;; esac
    done
    ' 2>/dev/null

    # Чистим кэши сессии — иначе connect() скиппит весь boot
    rm -f "$MTKDIR/.state" "$MTKDIR/hwparam.json"

    cd "$MTKDIR" || exit 1
    echo "[attempt $n] starting mtk"
    python mtk.py da seccfg unlock 2>&1 | tee "$LOG"
    # при r/w: python mtk.py r seccfg "$LOGDIR/seccfg_read_$n.bin"

    # Маркеры прогресса
    grep -E "GET-HW-INFO|Security deny|Protocol|Erase \[|WRITE|lock_state|gpt" "$LOG" | tail -5

    # Стоп-условие: прочитанный GPT
    if [ -f /tmp/gpt.bin ] || [ -f "$MTKDIR/gpt.bin" ]; then
        echo "=== GPT READ SUCCESS — stopping ==="
        break
    fi
    # Защита от серийных EIO-каскадов: если телефон отвалился — ждём переподключения
    sleep 2
done
