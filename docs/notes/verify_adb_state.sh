#!/usr/bin/env bash
# verify_adb_state.sh — post-flash ADB-state harness for RMX3630 (MT6789).
# Host: Termux (rooted Android + OTG), run right after boot v6 is flashed.
# READ-ONLY: no device writes, no flashing, no reboot. --dry-run is DEFAULT
# and every adb call is wrapped in `timeout`.
#   bash docs/notes/verify_adb_state.sh            # dry run, safe
#   bash docs/notes/verify_adb_state.sh --live -v  # real probes (read-only)
# Exit: 0 SECURE_OK | 1 UNAUTHORIZED_STILL (pending) | 2 harness error
set -u

PROG=${0##*/}
DRY_RUN=1
VERBOSE=0
JSON=0
ADB_TIMEOUT=5

usage() {
  cat <<'EOF'
verify_adb_state.sh — prove (or disprove) SECURE_OK on the target after v6.

Usage: bash docs/notes/verify_adb_state.sh [options]

  --dry-run     print what would be probed, touch nothing (DEFAULT)
  --live        actually run the probes (read-only adb shell commands)
  -v, --verbose show captured values while collecting
  --json        emit one machine-readable JSON summary on stdout
  --timeout N   per-adb-call timeout in seconds (default 5)
  -h, --help    this text

Verdicts: SECURE_OK (ro.adb.secure=0 AND `adb shell id` = uid=0),
          UNAUTHORIZED_STILL (anything else; the block names the Q1/Q2 next
          step), DRY_RUN (nothing probed, the default).
Exit codes: 0 OK, 1 pending/unauthorized, 2 harness error.
Env: ANDROID_SERIAL selects the target when several are attached.
EOF
}

die() { printf '%s: error: %s\n' "$PROG" "$*" >&2; exit 2; }
say() { if [ "$JSON" = 1 ]; then printf '%s\n' "$*" >&2; else printf '%s\n' "$*"; fi; }
vsay() { if [ "$VERBOSE" = 1 ]; then say "$*"; fi; return 0; }

# cap VAR <command...> — the only path to adb, always under `timeout`.
# Dry run: prints the planned command and leaves VAR empty.
cap() {
  _dst=$1; shift
  if [ "$DRY_RUN" = 1 ]; then
    say "  [dry-run] timeout ${ADB_TIMEOUT}s $*"
    return 0
  fi
  _val=$(timeout "$ADB_TIMEOUT" "$@" 2>&1)
  printf -v "$_dst" '%s' "$_val"
}

jstr() {
  if [ -z "${1-}" ]; then printf '""'; return 0; fi
  printf '"%s"' "$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\r//g' \
    | awk 'BEGIN{ORS=""} {if (NR>1) printf "\\n"; printf "%s", $0}')"
}

USB=""
collect_usb() {
  USB=""
  if [ "$DRY_RUN" = 1 ]; then
    say "  [dry-run] scan /sys/bus/usb/devices/*/{idVendor,idProduct,manufacturer,product,serial}"
    return 0
  fi
  for d in /sys/bus/usb/devices/*; do
    [ -r "$d/idVendor" ] || continue
    _vid=$(cat "$d/idVendor" 2>/dev/null) || continue
    USB="${USB}${d##*/} ${_vid}:$(cat "$d/idProduct" 2>/dev/null) man=$(cat "$d/manufacturer" 2>/dev/null || echo '?') prod=$(cat "$d/product" 2>/dev/null || echo '?') ser=$(cat "$d/serial" 2>/dev/null || echo '?')"$'\n'
  done
  [ -n "$USB" ] || USB="(no USB devices)"
}

# ---------------------------------------------------------------- arguments
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --dry-run) DRY_RUN=1 ;;
    --live) DRY_RUN=0 ;;
    -v|--verbose) VERBOSE=1 ;;
    --json) JSON=1 ;;
    --timeout|--timeout=*)
      case "$1" in
        --timeout) [ $# -ge 2 ] || die "--timeout needs a value"; _tv=$2; shift ;;
        *) _tv=${1#*=} ;;
      esac
      case "$_tv" in ''|*[!0-9]*) die "--timeout must be a positive integer" ;; esac
      [ "$_tv" -gt 0 ] || die "--timeout must be > 0"
      ADB_TIMEOUT=$_tv ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

if [ "$DRY_RUN" = 0 ]; then
  command -v adb >/dev/null 2>&1 || die "adb not found in PATH"
  command -v timeout >/dev/null 2>&1 || die "timeout(1) not found"
fi

if [ "$DRY_RUN" = 1 ]; then MODE="DRY RUN (default)"; else MODE="LIVE (read-only)"; fi
say "verify_adb_state.sh — $MODE, timeout=${ADB_TIMEOUT}s, serial=${ANDROID_SERIAL:-auto}"
say ""

# ---------------------------------------------------------------- collection
say "[1/4] USB enumeration"
collect_usb
if [ "$DRY_RUN" = 0 ]; then printf '%s' "$USB" | sed 's/^/  /'; fi

say ""
say "[2/4] adb transport"
ADB_DEVICES="" ADB_STATE=""
cap ADB_DEVICES adb devices -l
cap ADB_STATE adb get-state
[ "$DRY_RUN" = 0 ] && [ -n "$ADB_DEVICES" ] && printf '%s\n' "$ADB_DEVICES" | sed 's/^/  /'
vsay "  state: $ADB_STATE"

AUTH=0; case "$ADB_STATE" in device) AUTH=1 ;; esac
printf '%s\n' "$ADB_DEVICES" | grep -qE '^[[:space:]]*[^[:space:]]+[[:space:]]+device([[:space:]]|$)' && AUTH=1

PROP_SECURE="" PROP_DEBUGGABLE="" PROP_RO_SECURE="" PROP_BTYPE="" PROP_BUILD_TYPE=""
SHELL_ID="" ADBKEYS_LS="" ADBPROPS="" SU_ID="" CMDLINE="" BOOTCONFIG="" DMESG="" CONFIG_GZ=""
ROOT=0

say "[3/4] target properties / shell identity (needs an authorized transport)"
if [ "$AUTH" = 1 ] || [ "$DRY_RUN" = 1 ]; then
  cap PROP_SECURE adb shell getprop ro.adb.secure
  cap PROP_DEBUGGABLE adb shell getprop ro.debuggable
  cap PROP_RO_SECURE adb shell getprop ro.secure
  cap PROP_BTYPE adb shell getprop ro.product.build.type
  cap PROP_BUILD_TYPE adb shell getprop ro.build.type
  cap SHELL_ID adb shell id
  cap ADBKEYS_LS adb shell ls -l /data/misc/adb
  cap ADBPROPS adb shell 'getprop | grep -i adb'
  if [ "$DRY_RUN" = 0 ]; then
    say "  ro.adb.secure=$PROP_SECURE ro.debuggable=$PROP_DEBUGGABLE ro.secure=$PROP_RO_SECURE build=${PROP_BTYPE:-?}/${PROP_BUILD_TYPE:-?}"
    say "  id: $(printf '%s' "$SHELL_ID" | head -n1)"
    vsay "  /data/misc/adb: $ADBKEYS_LS"
    vsay "  adb props: $ADBPROPS"
  fi
else
  say "  skipped: transport not authorized (shell probes need \`device\`)"
fi

say "[4/4] root-only evidence: bootconfig / init / avb (needs su)"
if [ "$AUTH" = 1 ] || [ "$DRY_RUN" = 1 ]; then
  cap SU_ID adb shell 'su -c id'
  case "$SU_ID" in *uid=0*) ROOT=1 ;; esac
  if [ "$ROOT" = 1 ] || [ "$DRY_RUN" = 1 ]; then
    cap CMDLINE adb shell 'cat /proc/cmdline'
    cap BOOTCONFIG adb shell 'cat /proc/bootconfig 2>/dev/null | head -n 40'
    cap DMESG adb shell "dmesg | grep -iE 'init|ramdisk|avb|androidboot' | tail -n 40"
    cap CONFIG_GZ adb shell 'ls -l /proc/config.gz'
    if [ "$DRY_RUN" = 0 ]; then
      say "  su: $(printf '%s' "$SU_ID" | head -n1)  /proc/config.gz: ${CONFIG_GZ:-absent}"
      vsay "  /proc/cmdline: $CMDLINE"
      vsay "  dmesg hits: $DMESG"
    fi
  elif [ "$DRY_RUN" = 0 ]; then
    say "  skipped: no root (su -c id: $(printf '%s' "$SU_ID" | head -n1))"
  fi
else
  say "  skipped: transport not authorized"
fi

# ---------------------------------------------------------------- verdict
if [ "$DRY_RUN" = 1 ]; then
  VERDICT=DRY_RUN; RC=0
  DETAIL="nothing probed; run --live after flashing v6"
elif [ "$AUTH" != 1 ]; then
  VERDICT=UNAUTHORIZED_STILL; RC=1
  DETAIL="adb transport not authorized (state=${ADB_STATE:-unknown})"
elif [ "$PROP_SECURE" = "0" ] && printf '%s' "$SHELL_ID" | grep -q 'uid=0'; then
  VERDICT=SECURE_OK; RC=0
  DETAIL="ro.adb.secure=0 and shell uid=0"
else
  VERDICT=UNAUTHORIZED_STILL; RC=1
  DETAIL="authorized but not SECURE_OK: ro.adb.secure=${PROP_SECURE:-?}; id=$(printf '%s' "$SHELL_ID" | head -n1)"
fi

if [ "$JSON" = 0 ]; then
  say "================ VERDICT ================"
  say "verdict : $VERDICT"
  say "exit    : $RC"
  say "detail  : $DETAIL"
  if [ "$VERDICT" != SECURE_OK ]; then
    say "----------------------------------------"
    say "next step (Q1 vs Q2 discriminator):"
    say "  cmd     : adb shell getprop ro.debuggable"
    say "  value 1 : Q2 — our patched init ran, property gate still rejects ro.adb.secure"
    say "  value 0 : Q1 — patched boot init never ran (vendor_boot init wins)"
    say "  confirm : adb shell ls -l /init   (size 3143536 => boot-ramdisk init => Q2)"
    say "  no shell: offline — checklist #8 (vendor_boot /init presence)"
  fi
  say "========================================="
else
  printf '{"tool":"verify_adb_state.sh","dry_run":%s,"timeout_s":%s,"verdict":"%s","exit_code":%s,' \
    "$([ "$DRY_RUN" = 1 ] && echo true || echo false)" "$ADB_TIMEOUT" "$VERDICT" "$RC"
  printf '"mode":%s,"detail":%s,' "$(jstr "$MODE")" "$(jstr "$DETAIL")"
  printf '"adb":{"devices":%s,"state":%s,"authorized":%s},' \
    "$(jstr "$ADB_DEVICES")" "$(jstr "$ADB_STATE")" \
    "$([ "$AUTH" = 1 ] && echo true || echo false)"
  printf '"usb":[%s],' "$(printf '%s\n' "$USB" | awk 'NF{if(n++)printf ",";gsub(/\\/,"\\\\");gsub(/"/,"\\\"");printf "\"%s\"",$0}')"
  printf '"props":{"ro.adb.secure":%s,"ro.debuggable":%s,"ro.secure":%s,"ro.product.build.type":%s,"ro.build.type":%s},' \
    "$(jstr "$PROP_SECURE")" "$(jstr "$PROP_DEBUGGABLE")" "$(jstr "$PROP_RO_SECURE")" \
    "$(jstr "$PROP_BTYPE")" "$(jstr "$PROP_BUILD_TYPE")"
  printf '"root":%s,"shell_id":%s,"su_id":%s,"cmdline":%s,"bootconfig":%s,"dmesg":%s,"config_gz":%s,' \
    "$([ "$ROOT" = 1 ] && echo true || echo false)" "$(jstr "$SHELL_ID")" "$(jstr "$SU_ID")" \
    "$(jstr "$CMDLINE")" "$(jstr "$BOOTCONFIG")" "$(jstr "$DMESG")" "$(jstr "$CONFIG_GZ")"
  printf '"adb_keys_ls":%s,' "$(jstr "$ADBKEYS_LS")"
  printf '"next_step":{"command":"adb shell getprop ro.debuggable","q2_expected":"1","q1_expected":"0",'
  printf '"confirm":"adb shell ls -l /init","confirm_q2_size":"3143536"}}\n'
fi

exit "$RC"
