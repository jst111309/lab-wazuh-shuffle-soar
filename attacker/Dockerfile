# =============================================================================
# attacker — mesin simulasi serangan (Ubuntu 22.04)
#   Hanya untuk lab: menguji deteksi Wazuh & respons Shuffle terhadap
#   endpoint-1 (SSH Gateway) dan endpoint-2 (Web Server) di network soc-net.
# =============================================================================
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Tool pengujian & utilitas jaringan
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap hydra sshpass openssh-client \
        curl ca-certificates iputils-ping netcat-openbsd iproute2 procps \
    && rm -rf /var/lib/apt/lists/*

# /scripts : script pengujian per skenario (di-mount dari attacker/scripts)
# /results : hasil uji 10x (di-mount dari tests/results)
RUN mkdir -p /scripts /results
WORKDIR /scripts

# Container tetap hidup, menunggu perintah lewat `docker exec`
CMD ["sleep", "infinity"]
