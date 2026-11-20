#!/bin/bash
# =============================================================================
# Unduh rule komunitas ET Open (lengkap) untuk Suricata 6.0.4, lalu reload rule.
#   - Resume otomatis bila koneksi putus (internet lambat / tidak stabil)
#   - Hasil disimpan di /var/lib/suricata/rules (volume) -> cukup sekali
#   - Suricata memuat rule baru tanpa restart (sinyal USR2)
# Jalankan manual (paksa unduh ulang):  docker exec endpoint-1 et-open-update.sh --force
# Log proses:                           /var/log/suricata/et-open-update.log
# =============================================================================
URL="https://rules.emergingthreats.net/open/suricata-6.0.4/emerging.rules.tar.gz"
DIR=/var/lib/suricata/rules
TMP=/var/lib/suricata/et-open.tar.gz
LOG=/var/log/suricata/et-open-update.log

log() { echo "$(date '+%F %T') [et-open] $*" | tee -a "$LOG"; }

mkdir -p "$DIR"
[ "$1" = "--force" ] && rm -f "$TMP"

for i in $(seq 1 120); do
    if tar tzf "$TMP" >/dev/null 2>&1; then
        break
    fi
    curl -sS -L -C - --connect-timeout 20 --speed-time 30 --speed-limit 1000 \
         -o "$TMP" "$URL" 2>>"$LOG"
    tar tzf "$TMP" >/dev/null 2>&1 && break
    log "percobaan $i: belum lengkap ($(stat -c %s "$TMP" 2>/dev/null || echo 0) byte), ulang 10 detik"
    sleep 10
done

if ! tar tzf "$TMP" >/dev/null 2>&1; then
    log "GAGAL: unduhan ET Open tidak lengkap. Coba lagi nanti dengan: et-open-update.sh"
    exit 1
fi

WORK=$(mktemp -d)
tar xzf "$TMP" -C "$WORK"
cat "$WORK"/rules/*.rules > "$DIR/et-open.rules.new"
mv "$DIR/et-open.rules.new" "$DIR/et-open.rules"
[ -f "$WORK/rules/classification.config" ] && cp "$WORK/rules/classification.config" "$DIR/classification.config"
[ -f "$WORK/rules/reference.config" ]      && cp "$WORK/rules/reference.config"      "$DIR/reference.config"
rm -rf "$WORK"

log "selesai: $(grep -c '^alert' "$DIR/et-open.rules") rule aktif ET Open"

# Reload rule Suricata tanpa restart
if pkill -USR2 -x Suricata-Main; then
    log "Suricata diminta memuat ulang rule (USR2)"
fi
