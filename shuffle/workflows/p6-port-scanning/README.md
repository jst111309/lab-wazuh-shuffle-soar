# P6 — Port Scanning Response

| | |
|---|---|
| Skenario | S6 Port scanning (endpoint-1, SSH Gateway, dideteksi Suricata) |
| Trigger | Wazuh rule **100601** (≥3 alert `CLO3 SCAN` Suricata local.rules / 60 detik / IP sama) atau **100603** (≥3 alert `ET SCAN` ET Open / 60 detik) |
| Decision | Threshold terlewati? IP valid? Bukan whitelist? (scan sekali = 100600/100602 hanya dicatat, tidak dikirim ke playbook) |
| Automated response | **Block IP** sumber di endpoint-1 (`firewall-drop180`, dibuka otomatis setelah 180 detik) |
| Verify | Cari rule **100700** (IP DIBLOKIR) di wazuh-indexer |
| Report | Laporan insiden ke Telegram |

## Alur workflow

```
webhook_p6 ─► analyze ─► decide ══[action = block]══► wazuh_login ─► respond ─► verify ─► report ─► kirim_telegram
```
Paling mirip P1. `decide` P6 mengeluarkan field yang sama dengan P1 (`ip`, `agent_id`, `ar_command`), jadi
**duplikat P1 → cukup ganti 3 hal: webhook, kode `decide`, kode `report`.**
Kondisi (`block`), `respond`, `verify`, `wazuh_login`, `kirim_telegram` **tidak diubah**.

## Konfigurasi node (yang berubah dari P1)

### 1. `webhook_p6` — Trigger Webhook
Start, salin ID webhook (harus berbeda dari P1).

### 3. `decide` — Shuffle Tools → Execute Python
Code: isi file [`decide.py`](decide.py)

### 7. `report` — Shuffle Tools → Execute Python
Code: isi file [`report.py`](report.py)

## Cara menguji

Satu kali scan nmap selesai < 1 detik → Suricata hanya mengeluarkan 1 alert (dibatasi 1 alert / 10 detik / IP) → rule 100600 (tidak di-block).
Agar melewati threshold, scan **berulang 3x** dengan jeda 12 detik:

```powershell
docker exec attacker sh -c "for i in 1 2 3; do nmap -sS -T4 --top-ports 200 10.20.0.11; sleep 12; done"
```
