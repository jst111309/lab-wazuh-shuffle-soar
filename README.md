# Lab Wazuh + Shuffle SOAR

Automated SOC lab: **Wazuh SIEM** detects attacks, **Shuffle SOAR** analyzes the alerts and triggers **automated incident response** (IP blocking, file quarantine, account lock) with Telegram bot notifications — fully containerized with Docker.

> Built as a university security engineering project (Project CLO 3 — SIEM + SOAR).
> ⚠️ **Lab only.** Default credentials are used on purpose. Do not expose this stack to the internet.

---

## Architecture

7 containers on one Docker network (`soc-net`, 10.20.0.0/24):

```
                     attack simulation
  ┌───────────┐ ───────────────────────────┐────────────────────┐
  │ attacker  │                            ▼                    ▼
  │  .100     │                     ┌────────────┐       ┌────────────┐
  └───────────┘                     │ endpoint-1 │       │ endpoint-2 │
                                    │ SSH gateway│       │ Web server │
                                    │ .11        │       │ .12        │
                                    └─────┬──────┘       └─────┬──────┘
                                          │ Wazuh agent (1514) │
                                          ▼                    ▼
           ┌──────────────────────────────────────────────────────────┐
           │ wazuh-manager .10 ──► wazuh-indexer .13 ◄── wazuh-dashboard .14 │
           └──────────────┬──────────────────────▲────────────────────┘
               webhook    │                      │  Wazuh API: active response
                          ▼                      │
                    ┌──────────────────────────────┐
                    │ shuffle .20 (SOAR playbooks) │ ──► Telegram bot
                    └──────────────────────────────┘
```

| Container | IP | Role | RAM limit |
|---|---|---|---|
| wazuh-manager | 10.20.0.10 | Log analysis, rules, active response, API | 1 GB |
| wazuh-indexer | 10.20.0.13 | Alert storage (OpenSearch) | 2 GB |
| wazuh-dashboard | 10.20.0.14 | Monitoring & evaluation UI | 768 MB |
| shuffle | 10.20.0.20 | SOAR playbooks, notifications | 2 GB |
| endpoint-1 | 10.20.0.11 | **SSH gateway** — Ubuntu 22.04, OpenSSH, Suricata IDS, iptables, Wazuh agent | 512 MB |
| endpoint-2 | 10.20.0.12 | **Web server** — Debian 12, nginx, OpenSSH (admin), sudo, Wazuh agent (FIM) | 256 MB |
| attacker | 10.20.0.100 | Attack simulation | 512 MB |

## Response flow

**Detect → Analyze → Decide → Respond → Verify → Report**

1. Wazuh agent ships endpoint logs to the manager; a rule fires an alert.
2. The manager forwards the alert to a Shuffle webhook.
3. The Shuffle playbook maps the alert fields, scores the risk and picks an action.
4. Shuffle calls the Wazuh API, which runs the active response on the endpoint.
5. Shuffle verifies the action and sends an incident report to Telegram.

## Attack scenarios

Each endpoint plays a different role, so each one produces different logs and alerts:

| # | Scenario | Target | Wazuh detection | SOAR response |
|---|---|---|---|---|
| 1 | SSH brute force | endpoint-1 (SSH gateway) | Many failed logins in `auth.log` | Block source IP |
| 2 | Unauthorized login | endpoint-1 (SSH gateway) | Login by an account outside the allow-list | Incident + notification |
| 6 | Port scanning | endpoint-1 (SSH gateway) | Suricata scan alert | Block IP above threshold |
| 3 | File integrity | endpoint-2 (web server) | Website / account file changed (FIM) | Incident + investigation |
| 4 | Malware | endpoint-2 (web server) | Uploaded file hash on the malware list | Quarantine file |
| 5 | Privilege escalation | endpoint-2 (web server) | `sudo` by a non-admin user | Alert + restrict access |

## Quick start

Requirements: Docker Desktop (WSL2 on Windows), ≥ 16 GB RAM on the host, 8 GB given to Docker.

```bash
# 1. Kernel setting for OpenSearch (Windows: run in PowerShell)
wsl -d docker-desktop sysctl -w vm.max_map_count=262144

# 2. Create your .env (see .env.example)
cp .env.example .env

# 3. Generate SSL certificates (once)
docker compose -f generate-indexer-certs.yml run --rm generator

# 4. Start the stack
docker compose up -d
```

Wazuh dashboard: <https://localhost> (user `admin`, password from `.env`).
Web server (endpoint-2): <http://localhost:8080>.

## Repository layout

```
├── docker-compose.yml           # all containers
├── generate-indexer-certs.yml   # SSL certificate generator
├── .env.example                 # copy to .env
├── wazuh/
│   ├── config/                  # manager, indexer, dashboard config
│   ├── rules/                   # custom detection rules
│   ├── lists/                   # CDB lists (allowed users, malware hashes)
│   └── active-response/         # custom response scripts
├── endpoint-1/                  # SSH gateway image (Ubuntu + Suricata)
├── endpoint-2/                  # web server image (Debian + nginx)
├── attacker/scripts/            # attack simulation scripts
├── shuffle/workflows/           # exported SOAR playbooks
├── tests/results/               # 10x test results per scenario
└── laporan/                     # report & screenshots
```

## Roadmap

| Stage | Status |
|---|---|
| 0. Environment setup | ✅ |
| 1. Wazuh deployment | 🔄 |
| 2. Wazuh ↔ Shuffle integration | ⏳ |
| 3. SOAR playbooks | ⏳ |
| 4. Automated response | ⏳ |
| 5. Testing (10x per scenario) | ⏳ |
| 6. Report & demo | ⏳ |

## Built with

- [Wazuh](https://wazuh.com) 4.14.10 (based on the official `wazuh-docker` single-node setup)
- [Shuffle](https://shuffler.io) SOAR
- Docker Compose
