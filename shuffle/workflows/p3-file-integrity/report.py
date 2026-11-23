# =============================================================================
# P3 File Integrity — node "report" (Shuffle Tools: Execute Python)
# VERIFY (insiden terbaca ulang dari datastore) + REPORT (laporan Telegram
# berisi hasil investigasi: jenis perubahan, hash, ukuran, diff).
#   Input : analyze, decide, create_incident (simpan), verify (baca ulang)
# Catatan: jangan tulis tanda dolar di komentar.
# =============================================================================
import json, ast
from datetime import datetime, timezone
from html import escape as h

a = json.loads(r'''$analyze.message''')
d = json.loads(r'''$decide.message''')
simpan_raw = r'''$create_incident'''
verify_raw = r'''$verify'''

def parse(teks):
    for f in (json.loads, ast.literal_eval):
        try:
            r = f(teks)
            return r if isinstance(r, dict) else {}
        except Exception:
            pass
    return {}

inc = d.get("incident", {})
inv = inc.get("investigasi", {})
inc_id = d.get("incident_id", "#")

simpan_ok = parse(simpan_raw).get("success") is True
verified = parse(verify_raw).get("success") is True and inc_id in verify_raw

def ts(teks):
    try:
        return datetime.strptime(teks, "%Y-%m-%dT%H:%M:%S.%f%z")
    except Exception:
        return None

t_alert = ts(a.get("timestamp", ""))
mttr = round((datetime.now(timezone.utc) - t_alert).total_seconds(), 1) if (t_alert and verified) else None
ikon = "✅" if verified else "❌"
pendek = lambda x: (str(x)[:12] + "…") if x and x != "-" else "-"

baris = [
    f"🚨 <b>{h(inc_id)}</b> · File Integrity · {h(inc.get('severity', '-'))}",
    "",
    f"<b>Detect</b>  : rule {h(str(a.get('rule_id')))} (level {a.get('rule_level')}) di {h(a.get('agent_name', '-'))}",
    f"<b>Analyze</b> : <code>{h(inc.get('file', '-'))}</code> — {h(inc.get('jenis_perubahan', '-'))}",
    f"<b>Investigasi</b>:",
    f"  • lokasi   : {h(inc.get('lokasi', '-'))}",
    f"  • atribut  : {h(', '.join(inv.get('atribut_berubah', [])) or '-')}",
    f"  • sha256   : {h(pendek(inv.get('sha256_sebelum')))} → {h(pendek(inv.get('sha256_sesudah')))}",
    f"  • ukuran   : {h(str(inv.get('ukuran_sebelum')))} → {h(str(inv.get('ukuran_sesudah')))} byte, pemilik {h(str(inv.get('pemilik')))}",
    f"  • 10 menit : {inv.get('perubahan_file_10m', 0)} perubahan file di agent ini",
    f"  • diff     : <code>{h(inv.get('diff', '-'))}</code>",
    f"<b>Decide</b>  : {h(inc.get('kategori', '-'))} — {h(d.get('reason', '-'))}",
    f"<b>Respond</b> : insiden dibuat (status OPEN) — {'tersimpan' if simpan_ok else 'GAGAL disimpan'}",
    f"<b>Verify</b>  : {ikon} {'insiden terbaca ulang dari datastore' if verified else 'insiden tidak ditemukan'}",
    f"<b>Rekomendasi</b>: {h(inc.get('rekomendasi', '-'))}",
    f"<b>Waktu</b>   : alert {h(a.get('timestamp', '-'))} · MTTR {f'{mttr:.0f} detik' if mttr is not None else '-'}",
]

print(json.dumps({
    "incident_id": inc_id,
    "playbook": "P3 File Integrity",
    "respond_ok": simpan_ok,
    "verified": verified,
    "mttr_seconds": mttr,
    "telegram_text": json.dumps("\n".join(baris), ensure_ascii=False)[1:-1],
}, ensure_ascii=False))
