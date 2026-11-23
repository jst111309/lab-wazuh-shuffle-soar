# =============================================================================
# P5 Privilege Escalation — node "report" (Shuffle Tools: Execute Python)
# VERIFY (baca hasil node "verify": rule 100704 akun DIKUNCI untuk user ini)
# + REPORT (laporan insiden Telegram)
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

# --- RESPOND: perintah kunci akun diterima Wazuh? ---
resp_ok = resp.get("error") == 0 and not resp.get("data", {}).get("failed_items")
resp_msg = resp.get("message", "tidak ada jawaban dari Wazuh API")

# --- VERIFY: rule 100704 (akun DIKUNCI) untuk user ini ditemukan? ---
hits = ver.get("hits", {}).get("hits", [])
src = hits[0]["_source"] if hits else {}
verified = bool(hits) and src.get("data", {}).get("dstuser") == d.get("user")

t_alert = ts(a.get("timestamp", ""))
t_lock = ts(src.get("timestamp", "")) if src else None
if verified and t_alert and t_lock:
    mttr = (t_lock - t_alert).total_seconds()
    mttr_txt = f"{mttr:.0f} detik"
else:
    mttr, mttr_txt = None, "-"

incident_id = "INC-P5-" + a.get("timestamp", "")[:19].replace("-", "").replace(":", "").replace("T", "-")
ikon = "✅" if verified else "❌"
status = f"BERHASIL — akun {d.get('user')} terkunci (rule 100704), dibuka otomatis {d.get('lock_seconds')} detik" if verified else "GAGAL / BELUM TERKONFIRMASI"

baris = [
    f"🔐 <b>{h(incident_id)}</b> · Privilege Escalation · {h(a.get('risiko', '-'))}",
    "",
    f"<b>Detect</b>  : rule {h(str(a.get('rule_id')))} (level {a.get('rule_level')}) di {h(a.get('agent_name', '-'))}",
    f"<b>Analyze</b> : user <b>{h(d.get('user', '-'))}</b> → sudo ke {h(d.get('target_user', '-'))}, perintah <code>{h(d.get('command', '-'))}</code>",
    f"<b>Decide</b>  : KUNCI AKUN — {h(d.get('reason', '-'))}",
    f"<b>Respond</b> : disable-account {h(d.get('user', '-'))} di {h(a.get('agent_name', '-'))} — {h(resp_msg)}",
    f"<b>Verify</b>  : {ikon} {h(status)}",
    f"<b>Waktu</b>   : alert {h(a.get('timestamp', '-'))} · MTTR {mttr_txt}",
    f"<b>Rekomendasi</b>: investigasi aktivitas {h(d.get('user', '-'))}, cek /etc/sudoers, reset password sebelum akun dibuka permanen",
]

print(json.dumps({
    "incident_id": incident_id,
    "playbook": "P5 Privilege Escalation",
    "respond_ok": resp_ok,
    "verified": verified,
    "mttr_seconds": mttr,
    "telegram_text": json.dumps("\n".join(baris), ensure_ascii=False)[1:-1],
}, ensure_ascii=False))
