# =============================================================================
# P1 SSH Brute Force — node "report" (Shuffle Tools: Execute Python)
# VERIFY (baca hasil node "verify") + REPORT (susun laporan insiden Telegram)
#   Input : analyze (8 field), decide (keputusan), respond (jawaban Wazuh API),
#           verify (hasil pencarian rule 100700 di wazuh-indexer)
# Catatan: jangan tulis tanda dolar di komentar.
# =============================================================================
import json
from datetime import datetime, timezone
from html import escape as h

a = json.loads(r'''$analyze.message''')
d = json.loads(r'''$decide.message''')
respond_raw = r'''$respond.body'''
verify_raw = r'''$verify.body'''

def to_json(teks):
    try:
        return json.loads(teks)
    except Exception:
        return {}

def ts(teks):
    # format Wazuh: 2026-11-21T09:57:27.656+0000
    try:
        return datetime.strptime(teks, "%Y-%m-%dT%H:%M:%S.%f%z")
    except Exception:
        return None

resp = to_json(respond_raw)
ver = to_json(verify_raw)

# --- RESPOND: apakah Wazuh menerima perintah? ---
resp_ok = resp.get("error") == 0 and not resp.get("data", {}).get("failed_items")
resp_msg = resp.get("message", "tidak ada jawaban dari Wazuh API")

# --- VERIFY: apakah rule 100700 (IP DIBLOKIR) ditemukan di indexer? ---
hits = ver.get("hits", {}).get("hits", [])
t_alert = ts(a.get("timestamp", ""))
t_block = ts(hits[0]["_source"]["timestamp"]) if hits else None
verified = bool(hits)

if verified and t_alert and t_block:
    mttr = (t_block - t_alert).total_seconds()
    mttr_txt = f"{mttr:.0f} detik" if mttr >= 0 else "IP sudah terblokir sebelumnya"
else:
    mttr, mttr_txt = None, "-"

t_now = datetime.now(timezone.utc)
incident_id = "INC-P1-" + t_now.strftime("%Y%m%d-%H%M%S")
status = "BERHASIL" if verified else "GAGAL / BELUM TERKONFIRMASI"
ikon = "✅" if verified else "❌"

baris = [
    f"🚨 <b>{incident_id}</b> · SSH Brute Force · {h(a.get('risiko', '-'))}",
    "",
    f"<b>Detect</b>  : rule {h(str(a.get('rule_id')))} (level {a.get('rule_level')}) di {h(a.get('agent_name', '-'))}",
    f"<b>Analyze</b> : {h(a.get('description', '-'))}",
    f"<b>Decide</b>  : BLOCK — {h(d.get('reason', '-'))}",
    f"<b>Respond</b> : firewall-drop {h(d.get('ip', '-'))} selama {d.get('block_seconds')} detik — {h(resp_msg)}",
    f"<b>Verify</b>  : {ikon} {status}" + (f" (rule 100700 pada {hits[0]['_source']['timestamp']})" if verified else ""),
    f"<b>Waktu</b>   : alert {h(a.get('timestamp', '-'))} · MTTR {mttr_txt}",
    "",
    f"Alert ID {h(str(a.get('alert_id')))} · Source IP {h(str(a.get('source_ip')))} → Destination IP {h(str(a.get('destination_ip')))}",
]

print(json.dumps({
    "incident_id": incident_id,
    "playbook": "P1 SSH Brute Force",
    "respond_ok": resp_ok,
    "verified": verified,
    "mttr_seconds": mttr,
    "telegram_text": json.dumps("\n".join(baris), ensure_ascii=False)[1:-1],
}, ensure_ascii=False))
