# =============================================================================
# endpoint-2 — WEB SERVER (Debian 12)
#   Website perusahaan: nginx + folder upload.
#   nginx + OpenSSH (akses admin) + sudo + rsyslog + Wazuh agent
#   Skenario: 3. file integrity (halaman web), 4. malware (file upload),
#             5. privilege escalation (sudo)
# =============================================================================
FROM debian:12

ARG WAZUH_AGENT_VERSION=4.14.10-1
ENV DEBIAN_FRONTEND=noninteractive

# Paket dasar, web server, SSH admin, sudo, syslog
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg lsb-release procps iproute2 \
        nginx openssh-server sudo rsyslog \
    && rm -rf /var/lib/apt/lists/*

# Wazuh agent (versi harus sama dengan manager)
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
    && chmod 644 /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update && apt-get install -y wazuh-agent=${WAZUH_AGENT_VERSION} \
    && rm -rf /var/lib/apt/lists/*

# rsyslog: modul kernel log (imklog) tidak bisa jalan di container
RUN sed -i 's/^module(load="imklog"/#module(load="imklog"/' /etc/rsyslog.conf

# SSH: hanya untuk akses admin, root tidak boleh login
RUN mkdir -p /run/sshd \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# User lab
#   sysadmin : admin server, boleh sudo (whitelist)
#   webdev   : developer web, TIDAK boleh sudo (aktor skenario privilege escalation)
RUN useradd -m -s /bin/bash sysadmin && echo 'sysadmin:Sysadm1n#Lab2026' | chpasswd \
    && usermod -aG sudo sysadmin \
    && useradd -m -s /bin/bash webdev && echo 'webdev:W3bdev#Lab2026' | chpasswd

# Website & folder upload
#   /var/www/html    : halaman website (dipantau FIM - skenario 3)
#   /var/www/uploads : file upload pengguna (dipantau FIM + hash - skenario 4)
COPY nginx/index.html /var/www/html/index.html
RUN rm -f /var/www/html/index.nginx-debian.html \
    && mkdir -p /var/www/uploads /var/quarantine \
    && chown -R webdev:www-data /var/www/html /var/www/uploads \
    && chmod 775 /var/www/html /var/www/uploads \
    && chmod 700 /var/quarantine

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80 22
ENTRYPOINT ["/entrypoint.sh"]
