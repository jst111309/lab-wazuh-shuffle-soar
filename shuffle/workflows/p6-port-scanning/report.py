# =============================================================================
# P6 Port Scanning — node "report" (Shuffle Tools: Execute Python)
# VERIFY (baca hasil node "verify": rule 100700 IP DIBLOKIR) + REPORT (Telegram)
#   Input : analyze, decide, respond (jawaban Wazuh API), verify (hasil indexer)
# Catatan: jangan tulis tanda dolar di komentar.
# =============================================================================
import json
from datetime import datetime
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
    try:
        return datetime.strptime(teks, "%Y-%m-%dT%H:%M:%S.%f%z")
    except Exception:
        return None

resp = to_json(respond_raw)
ver = to_json(verify_raw)

# --- RESPOND: perintah block diterima Wazuh? ---
resp_ok = resp.get("error") == 0 and not resp.get("data", {}).get("failed_items")
resp_msg = resp.get("message", "tidak ada jawaban dari Wazuh API")

# --- VERIFY: rule 100700 (IP DIBLOKIR) untuk IP ini ditemukan? ---
hits = ver.get("hits", {}).get("hits", [])
verified = bool(hits)
t_alert = ts(a.get("timestamp", ""))
t_block = ts(hits[0]["_source"]["timestamp"]) if hits else None
if verified and t_alert and t_block:
    mttr = (t_block - t_alert).total_seconds()
    mttr_txt = f"{mttr:.0f} detik" if mttr >= 0 else "IP sudah terblokir sebelumnya"
else:
    mttr, mttr_txt = None, "-"

incident_id = "INC-P6-" + a.get("timestamp", "")[:19].replace("-", "").replace(":", "").replace("T", "-")
ikon = "✅" if verified else "❌"
status = f"BERHASIL — IP {d.get('ip')} terblokir (rule 100700), dibuka otomatis {d.get('block_seconds')} detik" if verified else "GAGAL / BELUM TERKONFIRMASI"

baris = [
    f"📡 <b>{h(incident_id)}</b> · Port Scanning · {h(a.get('risiko', '-'))}",
    "",
    f"<b>Detect</b>  : rule {h(str(a.get('rule_id')))} (level {a.get('rule_level')}) di {h(a.get('agent_name', '-'))} — {h(d.get('sumber_rule', '-'))}",
    f"<b>Analyze</b> : {h(d.get('ip', '-'))} → {h(str(d.get('dest_ip', '-')))} (contoh port {h(str(d.get('dest_port', '-')))}), signature <i>{h(d.get('signature', '-'))}</i>",
    f"<b>Decide</b>  : BLOCK — {h(d.get('reason', '-'))}",
    f"<b>Respond</b> : firewall-drop {h(d.get('ip', '-'))} di {h(a.get('agent_name', '-'))} — {h(resp_msg)}",
    f"<b>Verify</b>  : {ikon} {h(status)}",
    f"<b>Waktu</b>   : alert {h(a.get('timestamp', '-'))} · MTTR {mttr_txt}",
    f"<b>Rekomendasi</b>: cek apakah IP {h(d.get('ip', '-'))} juga mencoba login (P1/P2), pertimbangkan blokir permanen di firewall perimeter",
]

print(json.dumps({
    "incident_id": incident_id,
    "playbook": "P6 Port Scanning",
    "respond_ok": resp_ok,
    "verified": verified,
    "mttr_seconds": mttr,
    "telegram_text": json.dumps("\n".join(baris), ensure_ascii=False)[1:-1],
}, ensure_ascii=False))
