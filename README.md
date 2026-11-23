# Lab Wazuh + Shuffle SOAR

Automated SOC lab: **Wazuh SIEM** detects attacks, **Shuffle SOAR** analyzes the alerts and triggers **automated incident response** (IP blocking, file quarantine, account lock, incident records) with Telegram bot notifications — fully containerized with Docker.

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
       webhook per        │                      │  Wazuh API: active response
       playbook (rule_id) ▼                      │  Indexer: verification queries
                    ┌──────────────────────────────┐
                    │ shuffle .20 (SOAR playbooks) │ ──► Telegram bot
                    └──────────────────────────────┘
```

| Container | IP | Role | RAM limit |
|---|---|---|---|
| wazuh-manager | 10.20.0.10 | Log analysis, custom rules, active response, API | 1 GB |
| wazuh-indexer | 10.20.0.13 | Alert storage (OpenSearch) | 2 GB |
| wazuh-dashboard | 10.20.0.14 | Monitoring & evaluation UI | 768 MB |
| shuffle | 10.20.0.20 | SOAR playbooks (Docker-in-Docker: frontend, backend, orborus, OpenSearch) | 2.5 GB |
| endpoint-1 | 10.20.0.11 | **SSH gateway** — Ubuntu 22.04, OpenSSH, Suricata IDS (ET Open + custom rules), iptables, Wazuh agent | 1.5 GB |
| endpoint-2 | 10.20.0.12 | **Web server** — Debian 12, nginx, OpenSSH (admin), sudo, Wazuh agent (realtime FIM) | 256 MB |
| attacker | 10.20.0.100 | Attack simulation | 512 MB |

## Response flow

**Detect → Analyze → Decide → Respond → Verify → Report**

1. **Detect** — the Wazuh agent ships logs / FIM events; a custom rule (group `clo3`) fires an alert.
2. The manager forwards the alert to the webhook of the matching playbook (one `<integration>` block per playbook, filtered by `rule_id`).
3. **Analyze** — the playbook maps the 8 alert fields (Alert ID, timestamp, rule ID, rule level, source IP, destination IP, agent, description), assigns a severity and, where needed, queries the indexer for context.
4. **Decide** — a branch condition decides whether to act (e.g. IP not whitelisted, change not caused by SOAR itself).
5. **Respond** — Shuffle calls the Wazuh API, which runs the active response on the endpoint, or records an incident.
6. **Verify** — Shuffle looks for proof in the indexer (e.g. rule 100700 "IP blocked") or reads the incident back.
7. **Report** — an incident report with MTTR is sent to Telegram.

## Attack scenarios & playbooks

One scenario = one Shuffle workflow (playbook):

| # | Scenario | Target | Wazuh rule | Playbook response | Status |
|---|---|---|---|---|---|
| 1 | SSH brute force | endpoint-1 | 100100, 100101 | **Block source IP** (`firewall-drop`, auto-unblock 180 s) | ✅ |
| 2 | Unauthorized login | endpoint-1 | 100200 | **Incident + notification** (investigates prior failed logins) | ✅ |
| 3 | File integrity | endpoint-2 | 100300, 100301 | **Incident + investigation** (diff, hashes, mass-change check) | ✅ |
| 4 | Malware | endpoint-2 | 100400 | **Quarantine file** (custom `clo3-quarantine.sh`) | ✅ |
| 5 | Privilege escalation | endpoint-2 | 100500, 100501 | **Lock account** (`disable-account`, auto-unlock 180 s) | ✅ |
| 6 | Port scanning | endpoint-1 | 100601, 100603 | **Block source IP** above threshold | ✅ |

### Detection rules (`wazuh/rules/local_rules.xml`)

| Range | Purpose |
|---|---|
| 100100 – 100603 | Scenario rules, built on top of built-in Wazuh rules (group `clo3`) |
| 100700 – 100705 | Verification rules: IP blocked/unblocked, file quarantined, account locked/unlocked (group `clo3_ar`) |

CDB list `wazuh/lists/clo3-malware-hashes` holds the EICAR test file hashes (harmless antivirus test file).

### Active responses (called by Shuffle through the Wazuh API)

| API command | Agent | Action | Verify rule |
|---|---|---|---|
| `firewall-drop180` | endpoint-1 | `iptables DROP <srcip>` for 180 s | 100700 / 100701 |
| `clo3-quarantine0` | endpoint-2 | move file to `/var/quarantine`, `chmod 000` | 100702 |
| `disable-account180` | endpoint-2 | lock the account for 180 s | 100704 / 100705 |

The responses are registered with a rule that never fires, so **Wazuh never acts on its own — Shuffle decides**. Shuffle uses two least-privilege accounts: `shuffle-soar` (Wazuh API: read agents + run active response) and `shuffle-reader` (indexer: read alerts only).

## Quick start

Requirements: Docker Desktop (WSL2 on Windows), ≥ 16 GB RAM on the host, 8 GB given to Docker.

```bash
# 1. Kernel setting for OpenSearch (Windows: run in PowerShell)
wsl -d docker-desktop sysctl -w vm.max_map_count=262144

# 2. Create your .env (see .env.example)
cp .env.example .env

# 3. Generate SSL certificates (once)
docker compose -f generate-indexer-certs.yml run --rm generator

# 4. Start the stack (first start downloads images, Suricata ET Open rules and Shuffle)
docker compose up -d
```

| UI | URL | Login |
|---|---|---|
| Wazuh dashboard | <https://localhost> | `admin` / password from `.env` |
| Shuffle | <https://localhost:3443> | create the first admin account in the browser |
| Web server (endpoint-2) | <http://localhost:8080> | – |

Then build the playbooks in Shuffle following `shuffle/workflows/p*/README.md`, and put each webhook ID into the matching `<integration>` block of `wazuh/config/wazuh_cluster/wazuh_manager.conf`. After changing that file, recreate the manager: `docker compose up -d --force-recreate wazuh.manager`.

## Repository layout

```
├── docker-compose.yml           # all 7 containers
├── generate-indexer-certs.yml   # SSL certificate generator
├── .env.example                 # copy to .env
├── wazuh/
│   ├── config/                  # manager (integrations, active responses), indexer, dashboard
│   ├── rules/local_rules.xml    # custom detection + verification rules
│   └── lists/                   # CDB list (malware hashes)
├── endpoint-1/                  # SSH gateway image (Ubuntu + Suricata, ET Open updater)
├── endpoint-2/                  # web server image (Debian + nginx, quarantine script)
├── attacker/                    # attack simulation image
├── shuffle/
│   ├── Dockerfile, docker-compose.yml, ...   # Shuffle in Docker-in-Docker
│   └── workflows/               # playbook code (Python nodes) + README per playbook
├── tests/results/               # 10x test results per scenario
└── laporan/                     # report & screenshots
```

## Roadmap

| Stage | Status |
|---|---|
| 0. Environment setup | ✅ |
| 1. Wazuh deployment (2 endpoints, FIM, Suricata, custom rules) | ✅ |
| 2. Wazuh ↔ Shuffle integration (webhook, 8-field mapping, Telegram) | ✅ |
| 3. SOAR playbooks | ✅ 6 / 6 |
| 4. Automated response (block IP, quarantine, lock account) | ✅ block IP (P1), quarantine (P4), lock account (P5) all live |
| 5. Testing (10x per scenario) | ⏳ |
| 6. Report & demo | ⏳ |

## Built with

- [Wazuh](https://wazuh.com) 4.14.10 (based on the official `wazuh-docker` single-node setup)
- [Shuffle](https://shuffler.io) SOAR
- [Suricata](https://suricata.io) 6.0.4 with [ET Open](https://rules.emergingthreats.net) rules
- Docker Compose
