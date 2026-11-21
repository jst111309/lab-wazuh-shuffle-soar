# P1 — SSH Brute Force Response

| | |
|---|---|
| Skenario | S1 SSH brute force (endpoint-1, SSH Gateway) |
| Trigger | Wazuh rule **100100** / **100101** (≥5 login gagal dalam 60 detik dari IP yang sama) |
| Decision | IP valid? Bukan whitelist komponen lab? Rule brute force? |
| Automated response | **Block IP** di endpoint-1 (`firewall-drop180`, dibuka otomatis setelah 180 detik) |
| Verify | Cari rule **100700** ("IP DIBLOKIR") di wazuh-indexer |
| Report | Laporan insiden ke Telegram (Detect → Analyze → Decide → Respond → Verify, MTTR) |

## Alur workflow

```
webhook_p1 ─► analyze ─► decide ══[action = block]══► wazuh_login ─► respond ─► verify ─► report ─► kirim_telegram
 (alert)      (8 field)  (cek IP)                    (token API)    (block IP)  (cek bukti) (insiden)  (notifikasi)
```

## Variabel workflow (tab Vars)

| Name | Isi |
|---|---|
| `telegram_token` | token bot Telegram |
| `telegram_chat_id` | chat_id grup |
| `wazuh_api_user` | `shuffle-soar` |
| `wazuh_api_password` | dari `.env` → `SHUFFLE_WAZUH_API_PASSWORD` |
| `indexer_user` | `shuffle-reader` |
| `indexer_password` | dari `.env` → `SHUFFLE_INDEXER_PASSWORD` |

## Konfigurasi node

### 1. `webhook_p1` — Trigger Webhook
Start, lalu salin ID webhook (`webhook_...`) untuk dipasang di Wazuh.

### 2. `analyze` — Shuffle Tools → Execute Python
Code: isi file [`../map-8-fields.py`](../map-8-fields.py)

### 3. `decide` — Shuffle Tools → Execute Python
Code: isi file [`decide.py`](decide.py)

**Kondisi pada garis `decide` → `wazuh_login`**: klik garisnya → *Add condition*
`$decide.message.action` **equals** `block`

### 4. `wazuh_login` — Http → POST
| Kolom | Isi |
|---|---|
| Url | `https://10.20.0.10:55000/security/user/authenticate?raw=true` |
| Username | `$wazuh_api_user` |
| Password | `$wazuh_api_password` |
| Verify | `false` |

### 5. `respond` — Http → PUT
| Kolom | Isi |
|---|---|
| Url | `https://10.20.0.10:55000/active-response?agents_list=$decide.message.agent_id` |
| Headers | 2 baris (tekan **Enter** di antaranya, JANGAN ketik tulisan `<br>`) — lihat blok di bawah |
| Body | `{"command": "$decide.message.ar_command", "alert": {"data": {"srcip": "$decide.message.ip"}}}` |
| Verify | `false` |

Isi kolom **Headers** node `respond` (persis 2 baris):
```
Authorization: Bearer $wazuh_login.body
Content-Type: application/json
```

### 6. `verify` — Http → POST, **Delay 15** (tab Setup)
| Kolom | Isi |
|---|---|
| Url | `https://10.20.0.13:9200/wazuh-alerts-*/_search` |
| Username | `$indexer_user` |
| Password | `$indexer_password` |
| Headers | `Content-Type: application/json` |
| Body | lihat di bawah |
| Verify | `false` |

```json
{"size":1,"sort":[{"timestamp":"desc"}],"_source":["timestamp","rule.description"],"query":{"bool":{"filter":[{"term":{"rule.id":"100700"}},{"term":{"agent.id":"$decide.message.agent_id"}},{"term":{"data.srcip":"$decide.message.ip"}},{"range":{"timestamp":{"gte":"now-4m"}}}]}}}
```

### 7. `report` — Shuffle Tools → Execute Python
Code: isi file [`report.py`](report.py)

### 8. `kirim_telegram` — Http → POST
| Kolom | Isi |
|---|---|
| Url | `https://api.telegram.org/bot$telegram_token/sendMessage` |
| Headers | `Content-Type: application/json` |
| Body | `{"chat_id": "$telegram_chat_id", "parse_mode": "HTML", "text": "$report.message.telegram_text"}` |
