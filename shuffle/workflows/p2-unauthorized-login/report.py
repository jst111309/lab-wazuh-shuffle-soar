# =============================================================================
# P2 Unauthorized Login — node "report" (Shuffle Tools: Execute Python)
# VERIFY (baca hasil node "verify": insiden terbaca kembali dari datastore)
# + REPORT (laporan insiden Telegram)
#   Input : analyze, decide, create_incident (simpan), verify (baca ulang)
# Catatan: jangan tulis tanda dolar di komentar.
# =============================================================================
import json
from datetime import datetime, timezone
from html import escape as h

a = json.loads(r'''$analyze.message''')
d = json.loads(r'''$decide.message''')
simpan_raw = r'''$create_incident'''
verify_raw = r'''$verify'''

inc = d.get("incident", {})
inv = inc.get("investigasi", {})

def parse(teks):
    # hasil Shuffle Tools bisa berupa JSON atau dict Python (tanda kutip tunggal)
    import ast
    for f in (json.loads, ast.literal_eval):
        try:
            r = f(teks)
            return r if isinstance(r, dict) else {}
        except Exception:
            pass
    return {}

simpan = parse(simpan_raw)
verify = parse(verify_raw)
inc_id = d.get("incident_id", "#")

# --- RESPOND: insiden tersimpan? (Shuffle Tools set_datastore_value) ---
simpan_ok = simpan.get("success") is True

# --- VERIFY: insiden bisa dibaca ulang dari datastore dengan ID yang sama? ---
verified = verify.get("success") is True and inc_id in verify_raw

def ts(teks):
    try:
        return datetime.strptime(teks, "%Y-%m-%dT%H:%M:%S.%f%z")
    except Exception:
        return None

t_alert = ts(a.get("timestamp", ""))
t_now = datetime.now(timezone.utc)
mttr = round((t_now - t_alert).total_seconds(), 1) if (t_alert and verified) else None
ikon = "✅" if verified else "❌"

baris = [
    f"🚨 <b>{h(d.get('incident_id', '-'))}</b> · Unauthorized Login · {h(inc.get('severity', '-'))}",
    "",
    f"<b>Detect</b>  : rule {h(str(a.get('rule_id')))} (level {a.get('rule_level')}) di {h(a.get('agent_name', '-'))}",
    f"<b>Analyze</b> : user <b>{h(inc.get('user', '-'))}</b> login SSH dari {h(inc.get('source_ip', '-'))} → {h(inc.get('destination_ip', '-'))}",
    f"<b>Investigasi</b>: {inv.get('login_gagal_15m', 0)} login gagal & {inv.get('alert_bruteforce_15m', 0)} alert brute force dari IP ini (15 menit)",
    f"<b>Decide</b>  : {h(inc.get('kategori', '-'))} — {h(d.get('reason', '-'))}",
    f"<b>Respond</b> : insiden dibuat (status OPEN) — {'tersimpan' if simpan_ok else 'GAGAL disimpan'}",
    f"<b>Verify</b>  : {ikon} {'insiden terbaca ulang dari datastore' if verified else 'insiden tidak ditemukan'}",
    f"<b>Rekomendasi</b>: {h(inc.get('rekomendasi', '-'))}",
    f"<b>Waktu</b>   : alert {h(a.get('timestamp', '-'))} · MTTR {f'{mttr:.0f} detik' if mttr is not None else '-'}",
]

print(json.dumps({
    "incident_id": d.get("incident_id"),
    "playbook": "P2 Unauthorized Login",
    "respond_ok": simpan_ok,
    "verified": verified,
    "mttr_seconds": mttr,
    "telegram_text": json.dumps("\n".join(baris), ensure_ascii=False)[1:-1],
}, ensure_ascii=False))
