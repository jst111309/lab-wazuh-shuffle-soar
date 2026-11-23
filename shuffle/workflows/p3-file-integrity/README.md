# P3 — File Integrity Response

| | |
|---|---|
| Skenario | S3 File Integrity Monitoring (endpoint-2, Web Server) |
| Trigger | Wazuh rule **100300** (file website `/var/www/html` berubah) / **100301** (`/etc/passwd`, `shadow`, `group`, `sudoers*` berubah) |
| Investigasi | Detail perubahan dari alert (jenis, atribut, hash sebelum/sesudah, ukuran, pemilik, **diff**) + jumlah perubahan file 10 menit terakhir + respons kunci akun SOAR 2 menit terakhir |
| Decision | **Lokasi** (website / sudoers / file akun) & **jenis** (added / modified / deleted) → kategori & severity. Perubahan `/etc/shadow` akibat kunci akun oleh SOAR → **skip** (bukan insiden). ≥5 perubahan / 10 menit → severity naik |
| Automated response | **Generate incident** + investigasi (datastore Shuffle, kategori `clo3_incidents`) + notifikasi |
| Verify | Insiden dibaca ulang dari datastore |
| Report | Laporan insiden + hasil investigasi ke Telegram |

## Alur workflow

```
webhook_p3 ─► analyze ─► investigate ─► decide ══[action = create_incident]══► create_incident ─► verify ─► report ─► kirim_telegram
```
Sama persis dengan P2 → cara tercepat: **duplikat workflow P2** lalu ganti webhook, body `investigate`, kode `decide` & `report`.

## Variabel workflow (tab Vars)

| Name | Isi |
|---|---|
| `telegram_token` | token bot Telegram |
| `telegram_chat_id` | `-1004497936631` |
| `indexer_user` | `shuffle-reader` |
| `indexer_password` | dari `.env` → `SHUFFLE_INDEXER_PASSWORD` |

## Konfigurasi node

### 1. `webhook_p3` — Trigger Webhook
Start, lalu salin ID webhook (`webhook_...`) untuk dipasang di Wazuh.

### 2. `analyze` — Shuffle Tools → Execute Python
Code: isi file [`../map-8-fields.py`](../map-8-fields.py)

### 3. `investigate` — Http → POST, **Delay 15** (tab Setup)
Delay 15 detik agar alert respons kunci akun (100704/100705) sempat masuk indexer sebelum dicari (indexer refresh ±5 detik + jeda Filebeat; delay 5 detik terbukti kadang kurang).

| Kolom | Isi |
|---|---|
| Url | `https://10.20.0.13:9200/wazuh-alerts-*/_search` |
| Username | `$indexer_user` |
| Password | `$indexer_password` |
| Headers | `Content-Type: application/json` |
| Verify | `false` |
| Body | lihat di bawah (satu baris) |

```json
{"size":0,"query":{"bool":{"filter":[{"term":{"agent.id":"$analyze.message.agent_id"}},{"range":{"timestamp":{"gte":"now-10m"}}}]}},"aggs":{"fim":{"filter":{"terms":{"rule.id":["550","553","554","100300","100301"]}},"aggs":{"files":{"terms":{"field":"syscheck.path","size":5}}}},"ar_akun":{"filter":{"bool":{"filter":[{"terms":{"rule.id":["100704","100705"]}},{"range":{"timestamp":{"gte":"now-2m"}}}]}}}}}
```

### 4. `decide` — Shuffle Tools → Execute Python
Code: isi file [`decide.py`](decide.py)

**Kondisi pada garis `decide` → `create_incident`**:
`$decide.message.action` **equals** `create_incident`

### 5. `create_incident` — Shuffle Tools → Set datastore value
| Kolom | Isi |
|---|---|
| Key | `$decide.message.incident_id` |
| Value | `$decide.message.incident` |
| Category | `clo3_incidents` |

### 6. `verify` — Shuffle Tools → Get datastore value
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
