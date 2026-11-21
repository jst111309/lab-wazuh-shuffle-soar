#!/bin/bash
# =============================================================================
# Persiapan & menjalankan Shuffle (berjalan di background, dipanggil entrypoint.sh)
#   1. Tunggu Docker engine internal siap
#   2. Siapkan folder data + kunci enkripsi + .env
#   3. docker compose up (ulang otomatis bila download image putus)
# Log: /var/log/shuffle-setup.log
# =============================================================================
# Tunggu dulu agar dockerd-entrypoint.sh (PID 1) selesai mengatur cgroup
sleep 10

cd /opt/shuffle
LOG=/var/log/shuffle-setup.log
log() { echo "$(date '+%F %T') [shuffle] $*" >> "$LOG"; }

log "1/3 menunggu Docker engine internal"
for i in $(seq 1 120); do
    docker info >/dev/null 2>&1 && break
    sleep 2
done
if ! docker info >/dev/null 2>&1; then
    log "GAGAL: Docker engine internal tidak menyala (lihat: docker logs shuffle)"
    exit 1
fi
log "Docker engine internal siap"

log "2/3 menyiapkan data, kunci enkripsi, .env"
mkdir -p data/shuffle-apps data/shuffle-files data/shuffle-database
chown -R 1000:1000 data/shuffle-database          # OpenSearch berjalan sebagai uid 1000
if [ ! -s data/.encryption_modifier ]; then
    head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32 > data/.encryption_modifier
    log "kunci enkripsi baru dibuat (data/.encryption_modifier)"
fi
cp shuffle.env.template .env
echo "SHUFFLE_ENCRYPTION_MODIFIER=$(cat data/.encryption_modifier)" >> .env

log "3/3 menjalankan Shuffle (download image pertama kali bisa lama)"
for i in $(seq 1 60); do
    if docker compose up -d >> "$LOG" 2>&1; then
        log "Shuffle berjalan: UI https://localhost:3443  |  webhook http://10.20.0.20:5001"
        exit 0
    fi
    log "percobaan $i gagal (kemungkinan download terputus), ulang 20 detik"
    sleep 20
done
log "GAGAL menjalankan Shuffle setelah 60 percobaan"
