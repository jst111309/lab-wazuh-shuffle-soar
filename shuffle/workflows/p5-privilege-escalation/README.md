# P5 — Privilege Escalation Response

| | |
|---|---|
| Skenario | S5 Privilege escalation (endpoint-2, Web Server) |
| Trigger | Wazuh rule **100500** (user tanpa hak mencoba `sudo`) / **100501** (`sudo` BERHASIL oleh user non-admin) |
| Decision | Pelaku = `srcuser` log sudo (bukan `dstuser`, yang berisi user tujuan = root). Akun dilindungi (`root`, `sysadmin`) → skip. Selain itu → **kunci akun** sesuai kebijakan "hanya sysadmin boleh sudo" |
| Automated response | **Kunci akun** di endpoint-2 (`disable-account180`, dibuka otomatis setelah 180 detik) |
| Verify | Cari rule **100704** (akun DIKUNCI) untuk user ini di wazuh-indexer |
| Report | Laporan insiden ke Telegram |

## Alur workflow

```
webhook_p5 ─► analyze ─► decide ══[action = lock]══► wazuh_login ─► respond ─► verify ─► report ─► kirim_telegram
```
Sama persis dengan P1 → cara tercepat: **duplikat workflow P1** lalu ganti webhook, kode `decide`, kondisi, body `respond`, body `verify`, kode `report`.

## Variabel workflow — sama dengan P1 (6 variabel)

## Konfigurasi node

### 1. `webhook_p5` — Trigger Webhook
Start, salin ID webhook (harus berbeda dari P1).

### 2. `analyze` — tidak diubah (map-8-fields.py)
Catatan: untuk log sudo, field `user` hasil analyze berisi `dstuser` (= root). Karena itu P5 mengambil pelaku dari alert asli (`srcuser`) di node `decide`.

### 3. `decide` — Shuffle Tools → Execute Python
Code: isi file [`decide.py`](decide.py)

**Kondisi pada garis `decide` → `wazuh_login`**: `$decide.message.action` **equals** `lock`

### 4. `wazuh_login` — tidak diubah dari P1

### 5. `respond` — Http → PUT
Url, Headers, Verify sama dengan P1. **Body** diganti:

```json
{"command": "$decide.message.ar_command", "alert": {"data": {"dstuser": "$decide.message.user"}}}
```

### 6. `verify` — Http → POST, Delay 15
Url, Username, Password, Headers, Verify sama dengan P1. **Body** diganti:

```json
{"size":1,"sort":[{"timestamp":"desc"}],"_source":["timestamp","rule.id","data.dstuser"],"query":{"bool":{"filter":[{"term":{"rule.id":"100704"}},{"term":{"agent.id":"$decide.message.agent_id"}},{"term":{"data.dstuser":"$decide.message.user"}},{"range":{"timestamp":{"gte":"now-4m"}}}]}}}
```

### 7. `report` — Shuffle Tools → Execute Python
Code: isi file [`report.py`](report.py)

### 8. `kirim_telegram` — tidak diubah dari P1

## Catatan
- Mengunci akun mengubah `/etc/shadow` → FIM memicu rule 100301 → playbook P3 mengenalinya sebagai perubahan oleh SOAR (alert 100704/100705) dan **skip** (tidak ada insiden palsu).
- Akun dibuka otomatis oleh Wazuh setelah 180 detik (rule 100705).
