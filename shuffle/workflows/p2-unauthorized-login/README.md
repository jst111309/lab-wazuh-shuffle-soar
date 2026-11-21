# P2 — Unauthorized Login Response

| | |
|---|---|
| Skenario | S2 Unauthorized login (endpoint-1, SSH Gateway) |
| Trigger | Wazuh rule **100200** (login SSH berhasil oleh user selain `sysadmin`) |
| Investigasi | Riwayat IP sumber 15 menit terakhir di wazuh-indexer (login gagal 5760/5710, brute force 100100/100101) |
| Decision | User di luar whitelist? Didahului brute force? → kategori & severity insiden |
| Automated response | **Generate incident** (disimpan di datastore Shuffle, kategori `clo3_incidents`) + notifikasi |
| Verify | Insiden dibaca ulang dari datastore dengan ID yang sama |
| Report | Laporan insiden ke Telegram |

## Alur workflow

```
webhook_p2 ─► analyze ─► investigate ─► decide ══[action = create_incident]══► create_incident ─► verify ─► report ─► kirim_telegram
 (alert)      (8 field)  (riwayat IP)   (nilai)                               (simpan insiden)   (baca ulang) (laporan) (notifikasi)
```

## Variabel workflow (tab Vars)

| Name | Isi |
|---|---|
| `telegram_token` | token bot Telegram |
| `telegram_chat_id` | `-1004497936631` |
| `indexer_user` | `shuffle-reader` |
| `indexer_password` | dari `.env` → `SHUFFLE_INDEXER_PASSWORD` |

P2 tidak memakai Wazuh API (tidak ada tindakan ke endpoint), jadi `wazuh_api_user/password` tidak perlu.

## Konfigurasi node

### 1. `webhook_p2` — Trigger Webhook
Start, lalu salin ID webhook (`webhook_...`) untuk dipasang di Wazuh.

### 2. `analyze` — Shuffle Tools → Execute Python
Code: isi file [`../map-8-fields.py`](../map-8-fields.py)

### 3. `investigate` — Http → POST
| Kolom | Isi |
|---|---|
| Url | `https://10.20.0.13:9200/wazuh-alerts-*/_search` |
| Username | `$indexer_user` |
| Password | `$indexer_password` |
| Headers | `Content-Type: application/json` |
| Verify | `false` |
| Body | lihat di bawah (satu baris) |

```json
{"size":0,"query":{"bool":{"filter":[{"term":{"agent.id":"$analyze.message.agent_id"}},{"term":{"data.srcip":"$analyze.message.source_ip"}},{"terms":{"rule.id":["5760","5710","100100","100101"]}},{"range":{"timestamp":{"gte":"now-15m"}}}]}},"aggs":{"per_rule":{"terms":{"field":"rule.id"}}}}
```

### 4. `decide` — Shuffle Tools → Execute Python
Code: isi file [`decide.py`](decide.py)

**Kondisi pada garis `decide` → `create_incident`**: klik garisnya → *New condition*
`$decide.message.action` **equals** `create_incident`

### 5. `create_incident` — Shuffle Tools → **Set datastore value**
| Kolom | Isi |
|---|---|
| Key | `$decide.message.incident_id` |
| Value | `$decide.message.incident` |
| Category | `clo3_incidents` |

### 6. `verify` — Shuffle Tools → **Get datastore value**
| Kolom | Isi |
|---|---|
| Key | `$decide.message.incident_id` |
| Category | `clo3_incidents` |

### 7. `report` — Shuffle Tools → Execute Python
Code: isi file [`report.py`](report.py)

### 8. `kirim_telegram` — Http → POST
| Kolom | Isi |
|---|---|
| Url | `https://api.telegram.org/bot$telegram_token/sendMessage` |
| Headers | `Content-Type: application/json` |
| Body | `{"chat_id": "$telegram_chat_id", "parse_mode": "HTML", "text": "$report.message.telegram_text"}` |

## Melihat daftar insiden
Shuffle → menu kiri **Admin** (ikon gedung) → **Datastore** → kategori `clo3_incidents`.
