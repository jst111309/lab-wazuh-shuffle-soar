# =============================================================================
# endpoint-1 — SSH GATEWAY (Ubuntu 22.04)
#   Server akses jarak jauh: pintu masuk admin ke jaringan.
#   OpenSSH + rsyslog + iptables + Suricata (IDS, ET Open + rule CLO3) + Wazuh agent
#   Skenario: 1. SSH brute force, 2. unauthorized login, 6. port scanning
# =============================================================================
FROM ubuntu:22.04

ARG WAZUH_AGENT_VERSION=4.14.10-1
ENV DEBIAN_FRONTEND=noninteractive

# Paket dasar, SSH, syslog, firewall, IDS
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg lsb-release procps net-tools iproute2 sudo \
        openssh-server rsyslog iptables suricata \
    && rm -rf /var/lib/apt/lists/*

# Wazuh agent (versi harus sama dengan manager)
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
    && chmod 644 /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update && apt-get install -y wazuh-agent=${WAZUH_AGENT_VERSION} \
    && rm -rf /var/lib/apt/lists/*

# iptables-legacy: paling kompatibel dengan kernel WSL2 untuk firewall-drop
RUN update-alternatives --set iptables /usr/sbin/iptables-legacy \
    && update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy

# rsyslog: modul kernel log (imklog) tidak bisa jalan di container
RUN sed -i 's/^module(load="imklog"/#module(load="imklog"/' /etc/rsyslog.conf

# SSH: izinkan login password, root tidak boleh login
RUN mkdir -p /run/sshd \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# User lab
#   sysadmin : admin sah (whitelist)   -> password kuat
#   victim   : akun lemah (sengaja)    -> password lemah
RUN useradd -m -s /bin/bash sysadmin && echo 'sysadmin:Sysadm1n#Lab2026' | chpasswd \
    && usermod -aG sudo sysadmin \
    && useradd -m -s /bin/bash victim && echo 'victim:password123' | chpasswd

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Pengunduh rule ET Open (lengkap) — dijalankan saat container start
COPY suricata/et-open-update.sh /usr/local/bin/et-open-update.sh
RUN chmod +x /usr/local/bin/et-open-update.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
