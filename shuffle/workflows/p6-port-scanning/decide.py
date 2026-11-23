# =============================================================================
# P6 Port Scanning — node "decide" (Shuffle Tools: Execute Python)
# DECIDE: block IP sumber HANYA jika scan melewati threshold.
#   - rule 100601 (CLO3 SCAN, Suricata local.rules) / 100603 (ET SCAN, ET Open)
#     = >= 3 alert scan dari IP yang sama dalam 60 detik  -> THRESHOLD terlewati
#   - scan sekali (100600/100602) tidak dikirim ke playbook ini (hanya dicatat Wazuh)
#   - IP sumber harus valid & BUKAN whitelist komponen SOC
#   Output memakai nama field yang SAMA dengan P1 (ip, agent_id, ar_command) sehingga
#   node respond & verify hasil duplikat P1 tidak perlu diubah.
# Garis decide -> wazuh_login diberi kondisi: action == block
# Catatan: jangan tulis tanda dolar di komentar (Shuffle membacanya sebagai variabel).
# =============================================================================
import json, ipaddress

a = json.loads(r'''$analyze.message''')
e = json.loads(r'''$exec''')

data = (e.get("all_fields", {}) or {}).get("data", {}) or {}
sig = (data.get("alert", {}) or {}).get("signature", "-")
sumber_rule = "Suricata local.rules (CLO3)" if sig.startswith("CLO3") else ("Suricata ET Open" if sig.startswith("ET ") else "Suricata")

WHITELIST = {
    "127.0.0.1", "10.20.0.1",                    # localhost, gateway/laptop
    "10.20.0.10", "10.20.0.13", "10.20.0.14",    # wazuh manager/indexer/dashboard
    "10.20.0.20",                                # shuffle
    "10.20.0.11", "10.20.0.12",                  # endpoint-1, endpoint-2
}
RULE_THRESHOLD = {"100601", "100603"}            # >= 3 alert scan / 60 detik / IP sama

ip = a.get("source_ip", "-")
rule_id = str(a.get("rule_id", ""))

try:
    ipaddress.ip_address(ip)
    ip_valid = True
except ValueError:
    ip_valid = False

if rule_id not in RULE_THRESHOLD:
    action, reason = "skip", f"rule {rule_id} belum melewati threshold (scan sekali hanya dicatat)"
elif not ip_valid:
    action, reason = "skip", f"IP sumber tidak valid ({ip})"
elif ip in WHITELIST:
    action, reason = "skip", f"IP {ip} ada di whitelist (komponen lab)"
else:
    action = "block"
    reason = f"IP {ip} bukan whitelist, scan berulang melewati threshold (>=3 alert / 60 detik, rule {rule_id})"

print(json.dumps({
    "action": action,
    "reason": reason,
    "ip": ip,
    "agent_id": a.get("agent_id", "001"),
    "ar_command": "firewall-drop180",
    "block_seconds": 180,
    "signature": sig,
    "sumber_rule": sumber_rule,
    "dest_ip": data.get("dest_ip", a.get("destination_ip", "-")),
    "dest_port": data.get("dest_port", "-"),
}, ensure_ascii=False))
