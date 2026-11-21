# =============================================================================
# P1 SSH Brute Force — node "decide" (Shuffle Tools: Execute Python)
# DECIDE: validasi IP & frekuensi -> BLOCK atau SKIP
#   Input : hasil node "analyze" (8 field)
#   Output: {"action": "block"|"skip", "reason": "...", ...}
# Catatan: jangan tulis tanda dolar di komentar (Shuffle membacanya sebagai variabel).
# =============================================================================
import json, ipaddress

a = json.loads(r'''$analyze.message''')

# IP komponen SOC & endpoint lab -> tidak boleh diblokir
WHITELIST = {
    "127.0.0.1", "10.20.0.1",                    # localhost, gateway/laptop
    "10.20.0.10", "10.20.0.13", "10.20.0.14",    # wazuh manager/indexer/dashboard
    "10.20.0.20",                                # shuffle
    "10.20.0.11", "10.20.0.12",                  # endpoint-1, endpoint-2
}
RULE_BRUTEFORCE = {"100100", "100101"}           # rule threshold: >=5 gagal / 60 detik

ip = a.get("source_ip", "-")
rule_id = str(a.get("rule_id", ""))

try:
    ipaddress.ip_address(ip)
    ip_valid = True
except ValueError:
    ip_valid = False

if not ip_valid:
    action, reason = "skip", f"IP sumber tidak valid ({ip})"
elif ip in WHITELIST:
    action, reason = "skip", f"IP {ip} ada di whitelist (komponen lab)"
elif rule_id not in RULE_BRUTEFORCE:
    action, reason = "skip", f"rule {rule_id} bukan rule brute force"
else:
    action, reason = "block", f"IP {ip} bukan whitelist, threshold 5 login gagal/60 detik terlewati (rule {rule_id})"

print(json.dumps({
    "action": action,
    "reason": reason,
    "ip": ip,
    "agent_id": a.get("agent_id", "001"),
    "ar_command": "firewall-drop180",
    "block_seconds": 180,
}))
