#!/bin/bash
# endpoint-1 (SSH Gateway): rsyslog -> sshd -> suricata -> wazuh-agent
set -e

echo "[endpoint-1] konfigurasi Wazuh agent"
if [ -f /config/ossec.conf ]; then
    cp /config/ossec.conf /var/ossec/etc/ossec.conf
    chown root:wazuh /var/ossec/etc/ossec.conf
    chmod 640 /var/ossec/etc/ossec.conf
fi

echo "[endpoint-1] 1/4 rsyslog"
rm -f /run/rsyslogd.pid
touch /var/log/auth.log /var/log/syslog
# rsyslog Ubuntu turun hak ke user "syslog" ($PrivDropToUser) -> file log harus
# dimiliki syslog, kalau tidak log SSH tidak tertulis & Wazuh tidak mendeteksi apa pun
chown syslog:adm /var/log/auth.log /var/log/syslog
rsyslogd

echo "[endpoint-1] 2/4 sshd"
/usr/sbin/sshd

echo "[endpoint-1] 3/4 suricata"
mkdir -p /var/log/suricata /var/lib/suricata/rules
rm -f /var/run/suricata.pid
touch /var/log/suricata/eve.json
# Rule ET Open disimpan di volume. Jika belum ada: pakai file kosong dulu,
# lalu unduh di background (Suricata tetap jalan dengan local.rules).
ET=/var/lib/suricata/rules
[ -f $ET/classification.config ] || cp /etc/suricata/classification.config $ET/
[ -f $ET/reference.config ]      || cp /etc/suricata/reference.config $ET/
[ -f $ET/et-open.rules ]         || touch $ET/et-open.rules
suricata -c /etc/suricata/suricata.yaml --af-packet -D
if [ ! -s $ET/et-open.rules ]; then
    echo "[endpoint-1] ET Open belum ada -> unduh di background (log: /var/log/suricata/et-open-update.log)"
    nohup et-open-update.sh >/dev/null 2>&1 &
else
    echo "[endpoint-1] ET Open: $(grep -c '^alert' $ET/et-open.rules) rule aktif"
fi

echo "[endpoint-1] 4/4 wazuh-agent"
/var/ossec/bin/wazuh-control start

# Tetap hidup & tampilkan log agent di `docker logs`
exec tail -F /var/ossec/logs/ossec.log
