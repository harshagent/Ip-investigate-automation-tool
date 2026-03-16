import requests
import ipaddress
import csv
import os
import time
import re

# ======================
# CONFIG
# ======================
VT_API_KEY = "88f9247c42b4f29d3997429c1ef5c7817e8068becfcb4e171855e0150da49b04"
ABUSE_API_KEY = "0270e4ecd73216ecf81f5c974b2bec2efcbf2ef83310af4309a3985b73aaf0809830b8c3ebb3a80c"

INPUT_FILE = "testing.txt"
MASTER_CSV = "all_results.csv"

RATE_LIMIT = 2

# ======================
# HELPERS
# ======================
def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def vt_lookup_hash(sha256_hash):
    """Scan file hash on VirusTotal"""
    try:
        url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
        headers = {"x-apikey": VT_API_KEY}
        r = requests.get(url, headers=headers, timeout=10)

        if r.status_code == 404:
            return "Not Found", "N/A"
        if r.status_code != 200:
            return "Error", "N/A"

        data = r.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats", {})
        total = sum(stats.values())
        malicious = stats.get("malicious", 0)
        percent = round((malicious / total) * 100, 2) if total else 0
        
        return percent, "Scanned"

    except Exception as e:
        return "Error", str(e)

def abuse_lookup_ip(ip):
    """Scan IP on AbuseIPDB"""
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        r = requests.get(url, headers=headers, params=params, timeout=10)

        if r.status_code == 200:
            return r.json()["data"]["abuseConfidenceScore"]
        return "Error"
    except Exception:
        return "Error"

def parse_input_line(line):
    """Extract IP, Hash, Comment, or Separator from a line"""
    line = line.strip()
    if not line: return None
    
    # Check for separator
    if line.startswith("---"):
        return {"type": "separator"}

    # Extract comment
    comment_match = re.search(r'\((.*?)\)', line)
    comment = comment_match.group(1) if comment_match else None
    
    # Remove comment from line for better matching
    clean_line = re.sub(r'\(.*?\)', '', line).strip()

    # Match IP
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', clean_line)
    if ip_match:
        ip = ip_match.group(0)
        if not is_private_ip(ip):
            return {"type": "ip", "value": ip, "comment": comment}
        else:
            return None

    # Match Hash (MD5, SHA1, SHA256)
    hash_match = re.search(r'\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b', clean_line)
    if hash_match:
        return {"type": "hash", "value": hash_match.group(0), "comment": comment}

    return None

# ======================
# MAIN SCAN
# ======================
print("\n=== INVESTIGATION STARTED ===")

if not os.path.exists(INPUT_FILE):
    print(f"Error: {INPUT_FILE} not found.")
    exit()

entries = []
with open(INPUT_FILE, "r") as f:
    for line in f:
        parsed = parse_input_line(line)
        if parsed:
            entries.append(parsed)

if not entries:
    print("No valid IPs or Hashes found in input.")
    exit()

# Grouping for curly braces logic
grouped_results = []
current_group = []

for entry in entries:
    if entry["type"] == "separator":
        if current_group:
            grouped_results.append(current_group)
            current_group = []
    else:
        current_group.append(entry)

if current_group:
    grouped_results.append(current_group)

# Processing
total_entries = sum(len(group) for group in grouped_results)
count = 0

all_processed_data = []

for group_idx, group in enumerate(grouped_results):
    processed_group = []
    for entry in group:
        count += 1
        val = entry["value"]
        etype = entry["type"]
        comment = entry["comment"]
        
        print(f"[{count}/{total_entries}] Scanning {etype}: {val}", end="")
        if comment: print(f" ({comment})")
        else: print()

        res = {}
        if etype == "ip":
            abuse_score = abuse_lookup_ip(val)
            res = {
                "type": "ip",
                "value": val,
                "comment": comment,
                "abuse": abuse_score,
                "vt": "No Hash"
            }
            print(f"   ↳ AbuseIPDB: {abuse_score}%")
            print(f"   ↳ VirusTotal: No Hash (IP only)")
        elif etype == "hash":
            vt_percent, vt_status = vt_lookup_hash(val)
            res = {
                "type": "hash",
                "value": val,
                "comment": comment,
                "abuse": "No IP",
                "vt": vt_percent
            }
            print(f"   ↳ AbuseIPDB: No IP (Hash only)")
            print(f"   ↳ VirusTotal: {vt_percent}%")
        
        processed_group.append(res)
        time.sleep(RATE_LIMIT)
    
    all_processed_data.append(processed_group)

# ======================
# DISPLAY RESULTS
# ======================
print("\n=== FINAL RESULTS ===")

for idx, group in enumerate(all_processed_data):
    if len(all_processed_data) > 1:
        print("{")
    
    for i, res in enumerate(group):
        if res["comment"]:
            print(f"# {res['value']} ({res['comment']})")
        
        v = res["value"]
        abuse = res["abuse"]
        vt = res["vt"]
        
        print(f"S.No: {i+1}, Target: {v}, AbuseIP: {abuse}{'%' if isinstance(abuse, (int, float)) else ''}, VT: {vt}{'%' if isinstance(vt, (int, float)) else ''}")

    if len(all_processed_data) > 1:
        print("}")
    if idx < len(all_processed_data) - 1:
        print("---")

# ======================
# CSV EXPORT
# ======================
with open(MASTER_CSV, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["Group", "S.No", "Type", "Value", "Comment", "AbuseIP %", "VT %"])
    
    for gidx, group in enumerate(all_processed_data):
        for sidx, res in enumerate(group):
            writer.writerow([
                gidx + 1,
                sidx + 1,
                res["type"],
                res["value"],
                res["comment"] or "",
                res["abuse"],
                res["vt"]
            ])

print(f"\n📁 Results saved to {MASTER_CSV}")
