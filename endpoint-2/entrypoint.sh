#!/bin/bash
# endpoint-2 (Web Server): rsyslog -> sshd -> nginx -> wazuh-agent
set -e

echo "[endpoint-2] konfigurasi Wazuh agent"
if [ -f /config/ossec.conf ]; then
    cp /config/ossec.conf /var/ossec/etc/ossec.conf
    chown root:wazuh /var/ossec/etc/ossec.conf
    chmod 640 /var/ossec/etc/ossec.conf
fi

echo "[endpoint-2] 1/4 rsyslog"
rm -f /run/rsyslogd.pid
touch /var/log/auth.log /var/log/syslog
rsyslogd

echo "[endpoint-2] 2/4 sshd"
/usr/sbin/sshd

echo "[endpoint-2] 3/4 nginx"
mkdir -p /var/log/nginx
touch /var/log/nginx/access.log /var/log/nginx/error.log
nginx

echo "[endpoint-2] 4/4 wazuh-agent"
/var/ossec/bin/wazuh-control start

# Tetap hidup & tampilkan log agent di `docker logs`
exec tail -F /var/ossec/logs/ossec.log
