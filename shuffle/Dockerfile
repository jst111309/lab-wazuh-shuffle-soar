# =============================================================================
# shuffle — Shuffle SOAR dalam 1 container (Docker-in-Docker)
#   Di dalamnya berjalan Docker engine sendiri yang menjalankan 4 komponen
#   resmi Shuffle: frontend, backend, orborus, opensearch (lihat docker-compose.yml).
#   Worker & app playbook juga dibuat di dalam container ini.
# =============================================================================
FROM docker:27.3.1-dind

# Tanpa TLS untuk Docker engine internal (hanya diakses dari dalam container)
ENV DOCKER_TLS_CERTDIR=""

RUN apk add --no-cache bash curl

WORKDIR /opt/shuffle
COPY docker-compose.yml shuffle.env.template entrypoint.sh setup.sh /opt/shuffle/
RUN chmod +x /opt/shuffle/entrypoint.sh /opt/shuffle/setup.sh

# 3001 = UI http, 3443 = UI https, 5001 = backend API & webhook (hanya di soc-net)
EXPOSE 3001 3443 5001
ENTRYPOINT ["/opt/shuffle/entrypoint.sh"]
