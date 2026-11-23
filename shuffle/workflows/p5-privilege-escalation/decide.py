# =============================================================================
# P5 Privilege Escalation — node "decide" (Shuffle Tools: Execute Python)
# DECIDE: tentukan KUNCI AKUN (lock) atau SKIP sesuai kebijakan akses.
#   - pelaku diambil dari srcuser log sudo (dstuser = user tujuan, biasanya root)
#   - akun yang DILINDUNGI (root, sysadmin) tidak pernah dikunci otomatis
#   - rule 100500: mencoba sudo tanpa hak | 100501: sudo BERHASIL oleh non-admin
#   Input : analyze (8 field), exec (alert asli: data.srcuser, data.command)
#   Output: {"action": "lock"|"skip", "reason", "user", "agent_id", "ar_command", ...}
# Garis decide -> wazuh_login diberi kondisi: action == lock
# Catatan: jangan tulis tanda dolar di komentar (Shuffle membacanya sebagai variabel).
# =============================================================================
import json

a = json.loads(r'''$analyze.message''')
e = json.loads(r'''$exec''')

data = (e.get("all_fields", {}) or {}).get("data", {}) or {}
pelaku = data.get("srcuser", "") or ""
tujuan = data.get("dstuser", "-")
perintah = data.get("command", "-")
rule_id = str(a.get("rule_id", ""))

DILINDUNGI = {"root", "sysadmin"}          # kebijakan: admin sah tidak dikunci otomatis
JENIS = {
    "100500": "mencoba sudo TANPA HAK (tidak terdaftar di sudoers)",
    "100501": "sudo BERHASIL oleh user non-admin (kemungkinan sudoers diubah)",
}

if rule_id not in JENIS:
    action, reason = "skip", f"rule {rule_id} bukan rule privilege escalation"
elif not pelaku:
    action, reason = "skip", "pelaku (srcuser) tidak terbaca dari log sudo"
elif pelaku in DILINDUNGI:
    action, reason = "skip", f"akun {pelaku} dilindungi kebijakan (admin sah), tidak dikunci otomatis"
else:
    action = "lock"
    reason = f"user {pelaku} {JENIS[rule_id]} → kunci akun sesuai kebijakan (hanya sysadmin boleh sudo)"

print(json.dumps({
    "action": action,
    "reason": reason,
    "user": pelaku,
    "target_user": tujuan,
    "command": perintah,
    "jenis": JENIS.get(rule_id, "-"),
    "agent_id": a.get("agent_id", "002"),
    "ar_command": "disable-account180",
    "lock_seconds": 180,
}, ensure_ascii=False))
