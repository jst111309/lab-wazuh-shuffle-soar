# =============================================================================
# CLO3 — Pemetaan 8 field alert Wazuh (dipakai di Shuffle Tools "Execute Python")
#
# Shuffle mengganti variabel exec (di baris json.loads) dengan JSON kiriman Wazuh:
#   { severity, pretext, title, text, rule_id, timestamp, id, all_fields: <alert> }
# Keluaran (print) berupa JSON 8 field + info tambahan untuk playbook & Telegram.
# Di node berikutnya dipanggil dengan: [dolar]map_8_fields.message.<field>
# PENTING: jangan menulis tanda dolar di komentar — Shuffle membacanya sebagai variabel.
# =============================================================================
import json

e = json.loads(r'''$exec''')
a = e.get("all_fields", {}) or {}
rule = a.get("rule", {}) or {}
data = a.get("data", {}) or {}
agent = a.get("agent", {}) or {}
syscheck = a.get("syscheck", {}) or {}

# IP endpoint (log SSH/sudo/FIM tidak membawa IP tujuan; tujuannya endpoint itu sendiri)
IP_ENDPOINT = {"endpoint-1": "10.20.0.11", "endpoint-2": "10.20.0.12"}

# Severity mengikuti pembagian dashboard Wazuh 4.x:
#   Critical >= 15 | High 12-14 | Medium 7-11 | Low 0-6
level = int(rule.get("level", 0) or 0)
if level >= 15:
    risiko = "Critical"
elif level >= 12:
    risiko = "High"
elif level >= 7:
    risiko = "Medium"
else:
    risiko = "Low"

hasil = {
    # --- 8 field wajib (PDF Langkah 2) ---
    "alert_id": e.get("id", "-"),
    "timestamp": e.get("timestamp", "-"),
    "rule_id": e.get("rule_id", rule.get("id", "-")),
    "rule_level": level,
    "source_ip": data.get("srcip") or data.get("src_ip") or "-",
    "destination_ip": data.get("dest_ip") or IP_ENDPOINT.get(agent.get("name"), agent.get("ip", "-")),
    "agent_name": agent.get("name", "-"),
    "description": e.get("title", rule.get("description", "-")),
    # --- tambahan untuk keputusan playbook ---
    "agent_id": agent.get("id", "-"),
    "risiko": risiko,
    "skenario": next((g for g in rule.get("groups", []) if g.startswith("clo3_s")), "-"),
    "user": data.get("dstuser") or data.get("srcuser") or "-",
    "file": syscheck.get("path", "-"),
    "sha256": syscheck.get("sha256_after", "-"),
}

# --- teks notifikasi Telegram (parse_mode HTML) ---
# html.escape: aman untuk HTML Telegram; json.dumps(...)[1:-1]: aman ditempel di
# dalam body JSON node Http (kirim_telegram, field "text").
from html import escape as h
baris = [
    f"🚨 <b>CLO3 SOC ALERT</b> — {h(risiko)}",
    "",
    f"<b>Deskripsi</b>: {h(str(hasil['description']))}",
    f"<b>Alert ID</b>: {h(str(hasil['alert_id']))}",
    f"<b>Waktu</b>: {h(str(hasil['timestamp']))}",
    f"<b>Rule</b>: {h(str(hasil['rule_id']))} (level {level})",
    f"<b>Agent</b>: {h(str(hasil['agent_name']))}",
    f"<b>Source IP</b>: {h(str(hasil['source_ip']))}",
    f"<b>Destination IP</b>: {h(str(hasil['destination_ip']))}",
]
hasil["telegram_text"] = json.dumps("\n".join(baris), ensure_ascii=False)[1:-1]

print(json.dumps(hasil, ensure_ascii=False))
