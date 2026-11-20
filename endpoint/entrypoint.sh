#!/bin/bash
# Menyalakan semua proses endpoint secara berurutan:
#   1. rsyslog  2. sshd  3. suricata (opsional)  4. wazuh-agent
set -e

echo "[endpoint] konfigurasi Wazuh agent"
if [ -f /config/ossec.conf ]; then
    cp /config/ossec.conf /var/ossec/etc/ossec.conf
    chown root:wazuh /var/ossec/etc/ossec.conf
    chmod 640 /var/ossec/etc/ossec.conf
fi

echo "[endpoint] 1/4 rsyslog"
rm -f /run/rsyslogd.pid
touch /var/log/auth.log /var/log/syslog
rsyslogd

echo "[endpoint] 2/4 sshd"
/usr/sbin/sshd

if [ "${ENABLE_SURICATA}" = "yes" ]; then
    echo "[endpoint] 3/4 suricata"
    mkdir -p /var/log/suricata
    rm -f /var/run/suricata.pid
    touch /var/log/suricata/eve.json
    suricata -c /etc/suricata/suricata.yaml --af-packet -D
else
    echo "[endpoint] 3/4 suricata dilewati (ENABLE_SURICATA=${ENABLE_SURICATA})"
fi

echo "[endpoint] 4/4 wazuh-agent"
/var/ossec/bin/wazuh-control start

# Tetap hidup & tampilkan log agent di `docker logs`
exec tail -F /var/ossec/logs/ossec.log
