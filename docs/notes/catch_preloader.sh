#!/system/bin/sh
# catch_preloader.sh — запустить В РУТ-ШЕЛЛЕ (su) на хосте.
# Ждёт появления 22d9:0006 (preloader VCOM) на шине и пищит/пишет.
# Остановка: Ctrl+C. Делать комбо на цели, пока крутится.
LOG=/data/data/com.termux/files/home/preloader_catch.log
: > "$LOG"
echo "waiting for 22d9:0006 ... do the button combo now (Ctrl+C to stop)"
while true; do
    OUT=$(lsusb 2>/dev/null)
    echo "$OUT" | grep -q "22d9:0006" && {
        echo "$(date +%H:%M:%S)  *** PRELOADER VCOM DETECTED (22d9:0006) ***" | tee -a "$LOG"
        echo "$OUT" | tee -a "$LOG"
        break
    }
    # полезный сайд-эффект: видно смену состояний цели
    echo "$OUT" | grep "22d9" >> "$LOG"
    sleep 0.2
done
echo "now run: cd /data/data/com.termux/files/home/mtkclient && python mtk.py r gpt"
