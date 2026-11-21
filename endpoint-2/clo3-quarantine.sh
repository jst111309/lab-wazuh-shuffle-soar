#!/bin/bash
# =============================================================================
# CLO3 active response — KARANTINA FILE (endpoint-2, playbook P4 Malware)
#   Dipanggil Wazuh execd (diperintah Shuffle lewat Wazuh API).
#   Input (stdin, protokol AR Wazuh 4.x):
#     {"command":"add","parameters":{"alert":{"syscheck":{"path":"/var/www/uploads/x"}}}}
#   Aksi : pindahkan file ke /var/quarantine/<waktu>_<nama>.quarantined, chmod 000
#   Log  : /var/ossec/logs/active-responses.log (format ar_log_json Wazuh)
#          -> dibaca agent -> rule 100702 (bukti untuk langkah VERIFY)
#   Aman : hanya file di bawah /var/www/uploads yang boleh dikarantina.
# =============================================================================
LOG=/var/ossec/logs/active-responses.log
QDIR=/var/quarantine
PROG="active-response/bin/clo3-quarantine.sh"

read -r INPUT

log_result() {   # $1=result  $2=file  $3=dest  $4=sha256  $5=reason
    local j
    j=$(jq -nc --arg r "$1" --arg f "$2" --arg d "$3" --arg s "$4" --arg why "$5" --arg p "$PROG" \
        '{version:1, command:"add", parameters:{program:$p},
          clo3:{action:"quarantine", result:$r, file:$f, dest:$d, sha256:$s, reason:$why}}')
    echo "$(date '+%Y/%m/%d %H:%M:%S') $PROG: $j" >> "$LOG"
}

CMD=$(echo "$INPUT" | jq -r '.command // empty' 2>/dev/null)
FILE=$(echo "$INPUT" | jq -r '.parameters.alert.syscheck.path // empty' 2>/dev/null)

# Hanya aksi "add" (karantina tidak punya "delete"/pembatalan otomatis)
[ "$CMD" = "add" ] || exit 0

# Pengaman: tolak path di luar folder upload atau path aneh
case "$FILE" in
    /var/www/uploads/*) ;;
    *) log_result "rejected" "$FILE" "" "" "path di luar /var/www/uploads"; exit 1 ;;
esac
case "$FILE" in *..*) log_result "rejected" "$FILE" "" "" "path tidak valid"; exit 1 ;; esac

if [ ! -f "$FILE" ]; then
    log_result "failed" "$FILE" "" "" "file tidak ditemukan"
    exit 1
fi

mkdir -p "$QDIR" && chmod 700 "$QDIR"
SHA=$(sha256sum "$FILE" | cut -d' ' -f1)
DEST="$QDIR/$(date '+%Y%m%d-%H%M%S')_$(basename "$FILE").quarantined"

if mv "$FILE" "$DEST" && chown root:root "$DEST" && chmod 000 "$DEST"; then
    log_result "success" "$FILE" "$DEST" "$SHA" ""
else
    log_result "failed" "$FILE" "$DEST" "$SHA" "gagal memindahkan file"
    exit 1
fi
