# =============================================================================
# P2 Unauthorized Login — node "decide" (Shuffle Tools: Execute Python)
# DECIDE: menilai login yang tidak diizinkan + hasil investigasi riwayat IP,
#         lalu menyiapkan data INSIDEN yang akan dicatat.
#   Input : analyze (8 field), investigate (riwayat login gagal IP ini 15 menit)
#   Output: {"action": "create_incident"|"skip", "incident_id", "incident", ...}
# Catatan: jangan tulis tanda dolar di komentar (Shuffle membacanya sebagai variabel).
# =============================================================================
import json

a = json.loads(r'''$analyze.message''')

def to_json(teks):
    try:
        return json.loads(teks)
    except Exception:
        return {}

inv = to_json(r'''$investigate.body''')
investigasi_ok = "aggregations" in inv
buckets = {b["key"]: b["doc_count"]
           for b in inv.get("aggregations", {}).get("per_rule", {}).get("buckets", [])}
gagal = buckets.get("5760", 0) + buckets.get("5710", 0)       # login gagal / user tak dikenal
brute = buckets.get("100100", 0) + buckets.get("100101", 0)   # alert brute force

ALLOWED_USERS = {"sysadmin"}                                   # kebijakan: hanya sysadmin boleh SSH
user = a.get("user", "-")
ip = a.get("source_ip", "-")

if user in ALLOWED_USERS or user == "-":
    action, reason = "skip", f"user {user} diizinkan / tidak terbaca"
    severity, kategori = a.get("risiko", "-"), "-"
elif brute > 0:
    action, severity = "create_incident", "Critical"
    kategori = "Brute force BERHASIL - kredensial kemungkinan bocor"
    reason = f"user {user} di luar whitelist, dan IP {ip} sebelumnya brute force ({brute} alert, {gagal} login gagal / 15 menit)"
elif gagal > 0:
    action, severity = "create_incident", "High"
    kategori = "Login tidak sah setelah percobaan gagal"
    reason = f"user {user} di luar whitelist, didahului {gagal} login gagal dari IP {ip} / 15 menit"
else:
    action, severity = "create_incident", "High"
    kategori = "Login akun tidak diizinkan"
    reason = f"user {user} di luar whitelist (hanya sysadmin yang boleh login SSH)"

ts = a.get("timestamp", "")                                     # 2026-11-21T11:16:44.489+0000
incident_id = "INC-P2-" + ts[:19].replace("-", "").replace(":", "").replace("T", "-")

incident = {
    "incident_id": incident_id,
    "playbook": "P2 Unauthorized Login",
    "status": "OPEN",
    "severity": severity,
    "kategori": kategori,
    "alert_id": a.get("alert_id"),
    "rule_id": a.get("rule_id"),
    "timestamp": ts,
    "user": user,
    "source_ip": ip,
    "destination_ip": a.get("destination_ip"),
    "agent_name": a.get("agent_name"),
    "investigasi": {"berhasil": investigasi_ok, "login_gagal_15m": gagal, "alert_bruteforce_15m": brute},
    "rekomendasi": f"reset password {user}, cek sesi aktif & riwayat perintah, tinjau kebijakan akun",
}

print(json.dumps({
    "action": action,
    "reason": reason,
    "incident_id": incident_id,
    "incident": incident,
}, ensure_ascii=False))
