#!/bin/sh
# =============================================================================
# shuffle (Docker-in-Docker)
#   - setup.sh di background: tunggu Docker siap -> siapkan data -> compose up
#   - dockerd-entrypoint.sh resmi WAJIB menjadi PID 1 (mengatur cgroup v2);
#     jika bukan PID 1 muncul "sed: write error" dan Docker internal gagal.
# =============================================================================
/opt/shuffle/setup.sh &
exec dockerd-entrypoint.sh dockerd
