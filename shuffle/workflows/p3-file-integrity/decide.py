# =============================================================================
# P3 File Integrity — node "decide" (Shuffle Tools: Execute Python)
# DECIDE: periksa LOKASI & JENIS perubahan file, validasi apakah perubahan
#         berasal dari respons otomatis SOAR, lalu siapkan data INSIDEN.
#   Input : analyze (8 field), exec (alert asli: detail syscheck/diff),
#           investigate (perubahan file lain 10 menit + respons kunci akun 2 menit)
#   Output: {"action": "create_incident"|"skip", "incident_id", "incident", ...}
# Catatan: jangan tulis tanda dolar di komentar (Shuffle membacanya sebagai variabel).
# =============================================================================
import json

a = json.loads(r'''$analyze.message''')
e = json.loads(r'''$exec''')

def to_json(teks):
    try:
        return json.loads(teks)
    except Exception:
        return {}

inv = to_json(r'''$investigate.body''')
investigasi_ok = "aggregations" in inv
aggs = inv.get("aggregations", {})
fim_total = aggs.get("fim", {}).get("doc_count", 0)
file_lain = [b["key"] for b in aggs.get("fim", {}).get("files", {}).get("buckets", [])]
ar_akun = aggs.get("ar_akun", {}).get("doc_count", 0)

sc = (e.get("all_fields", {}) or {}).get("syscheck", {}) or {}
path = sc.get("path", a.get("file", "-"))
event = sc.get("event", "-")
JENIS = {"added": "file BARU ditambahkan", "modified": "isi/atribut file DIUBAH", "deleted": "file DIHAPUS"}
jenis = JENIS.get(event, event)

# --- LOKASI perubahan ---
FILE_AKUN = ("/etc/passwd", "/etc/shadow", "/etc/group")
if path.startswith("/var/www/html"):
    lokasi, kategori, severity = "Website (/var/www/html)", "Website diubah - kemungkinan defacement", "High"
    rekomendasi = "bandingkan dengan backup & pulihkan halaman, cek akun webdev, log nginx & sesi SSH"
elif path.startswith("/etc/sudoers"):
    lokasi, kategori, severity = "Hak akses (sudoers)", "Hak sudo diubah - kemungkinan privilege escalation", "Critical"
    rekomendasi = "kembalikan sudoers dari backup, cek user yang mendapat hak sudo, audit login terakhir"
elif path in FILE_AKUN:
    lokasi, kategori, severity = "File akun (" + path + ")", "File akun kritis diubah", "High"
    rekomendasi = "cek akun/grup baru atau password berubah, bandingkan dengan backup, audit login terakhir"
else:
    lokasi, kategori, severity = path, "Perubahan file terpantau", a.get("risiko", "Medium")
    rekomendasi = "tinjau perubahan & pemilik file"

# --- VALIDASI: perubahan /etc/shadow akibat respons SOAR (disable-account) ---
dari_soar = path == "/etc/shadow" and ar_akun > 0
# --- banyak file berubah sekaligus (>= 5 dalam 10 menit) -> naikkan severity ---
massal = fim_total >= 5
if massal and severity == "High":
    severity = "Critical"
    kategori += " (perubahan massal)"

if dari_soar:
    action = "skip"
    reason = f"perubahan {path} berasal dari respons otomatis SOAR (kunci/buka akun, {ar_akun} alert 2 menit terakhir)"
else:
    action = "create_incident"
    reason = f"{jenis} di lokasi {lokasi}" + (f"; {fim_total} perubahan file dalam 10 menit" if fim_total > 1 else "")

diff = str(sc.get("diff", "-"))
if len(diff) > 400:
    diff = diff[:400] + " …(dipotong)"

ts = a.get("timestamp", "")
incident_id = "INC-P3-" + ts[:19].replace("-", "").replace(":", "").replace("T", "-")

incident = {
    "incident_id": incident_id,
    "playbook": "P3 File Integrity",
    "status": "OPEN",
    "severity": severity,
    "kategori": kategori,
    "alert_id": a.get("alert_id"),
    "rule_id": a.get("rule_id"),
    "timestamp": ts,
    "agent_name": a.get("agent_name"),
    "destination_ip": a.get("destination_ip"),
    "file": path,
    "lokasi": lokasi,
    "jenis_perubahan": event,
    "investigasi": {
        "berhasil": investigasi_ok,
        "atribut_berubah": sc.get("changed_attributes", []),
        "sha256_sebelum": sc.get("sha256_before", "-"),
        "sha256_sesudah": sc.get("sha256_after", "-"),
        "ukuran_sebelum": sc.get("size_before", "-"),
        "ukuran_sesudah": sc.get("size_after", "-"),
        "pemilik": sc.get("uname_after", "-"),
        "waktu_ubah": sc.get("mtime_after", "-"),
        "diff": diff,
        "perubahan_file_10m": fim_total,
        "file_lain_10m": file_lain,
    },
    "rekomendasi": rekomendasi,
}

print(json.dumps({
    "action": action,
    "reason": reason,
    "incident_id": incident_id,
    "incident": incident,
}, ensure_ascii=False))
