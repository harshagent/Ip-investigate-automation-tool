from flask import Flask, render_template, request, jsonify, send_file
import requests
import ipaddress
import re
import threading
import csv
import os
import time
import json
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed

# -----------------------------
# LOAD ENV
# -----------------------------
load_dotenv()

# Support multiple API keys (comma-separated) for bulk scanning
# Example .env:  VT_API_KEYS=key1,key2,key3
#                ABUSE_API_KEYS=key1,key2,key3
# Falls back to single-key format (VT_API_KEY / ABUSE_API_KEY)

def load_keys(multi_env, single_env):
    """Load API keys — supports comma-separated list or single key."""
    raw = os.getenv(multi_env, "")
    if raw.strip():
        return [k.strip() for k in raw.split(",") if k.strip()]
    single = os.getenv(single_env, "")
    if single.strip():
        return [single.strip()]
    return []

VT_API_KEYS = load_keys("VT_API_KEYS", "VT_API_KEY")
ABUSE_API_KEYS = load_keys("ABUSE_API_KEYS", "ABUSE_API_KEY")

if not VT_API_KEYS or not ABUSE_API_KEYS:
    print("❌ API keys not loaded. Set VT_API_KEY(S) and ABUSE_API_KEY(S) in .env")
    exit()

print(f"✅ Loaded {len(VT_API_KEYS)} VT key(s), {len(ABUSE_API_KEYS)} AbuseIPDB key(s)")

app = Flask(__name__)

MALICIOUS_FILE = "malicious_only.csv"
CACHE_FILE = "ip_cache.json"

# -----------------------------
# API KEY ROTATOR
# -----------------------------
class KeyRotator:
    """Round-robin API key rotation with per-key rate tracking."""

    def __init__(self, keys, daily_limit, per_minute_limit=None):
        self.keys = keys
        self.daily_limit = daily_limit
        self.per_minute_limit = per_minute_limit
        self.index = 0
        self.usage = {k: {"daily": 0, "minute_ts": [], "exhausted": False} for k in keys}
        self.lock = threading.Lock()

    def get_key(self):
        """Get the next available API key, rotating round-robin."""
        with self.lock:
            attempts = 0
            while attempts < len(self.keys):
                key = self.keys[self.index]
                self.index = (self.index + 1) % len(self.keys)
                info = self.usage[key]

                # Skip exhausted keys
                if info["exhausted"]:
                    attempts += 1
                    continue

                # Check daily limit
                if info["daily"] >= self.daily_limit:
                    info["exhausted"] = True
                    attempts += 1
                    continue

                # Check per-minute limit
                if self.per_minute_limit:
                    now = time.time()
                    info["minute_ts"] = [t for t in info["minute_ts"] if now - t < 60]
                    if len(info["minute_ts"]) >= self.per_minute_limit:
                        attempts += 1
                        continue

                # Use this key
                info["daily"] += 1
                if self.per_minute_limit:
                    info["minute_ts"].append(time.time())
                return key

            return None  # All keys exhausted

    def mark_exhausted(self, key):
        """Manually mark a key as exhausted (e.g. on 429 response)."""
        with self.lock:
            if key in self.usage:
                self.usage[key]["exhausted"] = True

    def total_remaining(self):
        with self.lock:
            return sum(
                max(0, self.daily_limit - self.usage[k]["daily"])
                for k in self.keys
            )

# VT free: 500 requests/day, 4 requests/min per key
vt_rotator = KeyRotator(VT_API_KEYS, daily_limit=500, per_minute_limit=4)
# AbuseIPDB free: 1000 requests/day per key
abuse_rotator = KeyRotator(ABUSE_API_KEYS, daily_limit=1000)

# -----------------------------
# LOCAL IP CACHE
# -----------------------------
ip_cache = {}
cache_lock = threading.Lock()

def load_cache():
    global ip_cache
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                ip_cache = json.load(f)
            print(f"📦 Loaded {len(ip_cache)} cached IP results")
        except Exception:
            ip_cache = {}

def save_cache():
    with cache_lock:
        try:
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(ip_cache, f)
        except Exception:
            pass

load_cache()

# -----------------------------
# GLOBAL SCAN STATE
# -----------------------------
scan_lock = threading.Lock()
scan_status = {
    "total": 0,
    "completed": 0,
    "results": [],
    "running": False,
    "stop_requested": False
}

# -----------------------------
# Extract IPs
# -----------------------------
def extract_ips(text):
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    unique_ips = set()
    for ip in ips:
        try:
            obj = ipaddress.ip_address(ip)
            if not obj.is_private:
                unique_ips.add(ip)
        except Exception:
            continue
    return list(unique_ips)

# -----------------------------
# VirusTotal (with key rotation)
# -----------------------------
def vt_lookup(ip, attempt=0):
    if attempt >= len(VT_API_KEYS):
        return "QUOTA"

    # Check cache first
    with cache_lock:
        if ip in ip_cache and "vt" in ip_cache[ip]:
            return ip_cache[ip]["vt"]

    key = vt_rotator.get_key()
    if key is None:
        return "QUOTA"

    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": key}
        r = requests.get(url, headers=headers, timeout=15)

        if r.status_code == 429:
            # Rate limited — mark this key and retry with another
            vt_rotator.mark_exhausted(key)
            return vt_lookup(ip, attempt + 1)

        if r.status_code != 200:
            return "ERROR"

        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        total = sum(stats.values())
        malicious = stats.get("malicious", 0)

        if total == 0:
            result = 0
        else:
            result = round((malicious / total) * 100, 2)

        # Cache the result
        with cache_lock:
            if ip not in ip_cache:
                ip_cache[ip] = {}
            ip_cache[ip]["vt"] = result

        return result
    except Exception:
        return "ERROR"

# -----------------------------
# AbuseIPDB (with key rotation)
# -----------------------------
def abuse_lookup(ip, attempt=0):
    if attempt >= len(ABUSE_API_KEYS):
        return "QUOTA"

    # Check cache first
    with cache_lock:
        if ip in ip_cache and "abuse" in ip_cache[ip]:
            return ip_cache[ip]["abuse"]

    key = abuse_rotator.get_key()
    if key is None:
        return "QUOTA"

    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        r = requests.get(url, headers=headers, params=params, timeout=15)

        if r.status_code == 429:
            abuse_rotator.mark_exhausted(key)
            return abuse_lookup(ip, attempt + 1)

        if r.status_code == 200:
            score = r.json()["data"]["abuseConfidenceScore"]

            # Cache the result
            with cache_lock:
                if ip not in ip_cache:
                    ip_cache[ip] = {}
                ip_cache[ip]["abuse"] = score

            return score

        return "ERROR"
    except Exception:
        return "ERROR"

# -----------------------------
# Process IP
# -----------------------------
def process_ip(ip, serial):
    if scan_status["stop_requested"]:
        return None

    try:
        if ipaddress.ip_address(ip).is_private:
            return None
    except Exception:
        return None

    # Add small delay to respect rate limits
    time.sleep(0.3)

    abuse = abuse_lookup(ip)
    vt = vt_lookup(ip)

    return {
        "S.No": serial,
        "IP": ip,
        "AbuseIP %": abuse,
        "VT Engine %": vt
    }

# -----------------------------
# Background Scan
# -----------------------------
def background_scan(ips):
    with scan_lock:
        scan_status["total"] = len(ips)
        scan_status["completed"] = 0
        scan_status["results"] = []
        scan_status["running"] = True
        scan_status["stop_requested"] = False

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(process_ip, ip, i + 1): ip
            for i, ip in enumerate(ips)
        }

        for future in as_completed(futures):
            if scan_status["stop_requested"]:
                break

            result = future.result()

            with scan_lock:
                if result:
                    scan_status["results"].append(result)
                scan_status["completed"] += 1

    # Save cache after scan completes
    save_cache()

    with scan_lock:
        scan_status["running"] = False

# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/start_scan", methods=["POST"])
def start_scan():
    if scan_status["running"]:
        return jsonify({"status": "already_running"})

    file = request.files.get("file")
    if not file:
        return jsonify({"status": "no_file"})

    content = file.read().decode("utf-8", errors="ignore")
    ips = extract_ips(content)

    if not ips:
        return jsonify({"status": "no_ips_found"})

    thread = threading.Thread(target=background_scan, args=(ips,))
    thread.start()

    return jsonify({
        "status": "started",
        "total_ips": len(ips),
        "vt_keys": len(VT_API_KEYS),
        "abuse_keys": len(ABUSE_API_KEYS),
        "cached_ips": len(ip_cache)
    })

@app.route("/progress")
def progress():
    return jsonify(scan_status)

@app.route("/stop_scan", methods=["POST"])
def stop_scan():
    scan_status["stop_requested"] = True
    return jsonify({"status": "stopping"})

@app.route("/api_status")
def api_status():
    """Check remaining API quota across all keys."""
    return jsonify({
        "vt_remaining": vt_rotator.total_remaining(),
        "abuse_remaining": abuse_rotator.total_remaining(),
        "cached_ips": len(ip_cache)
    })

@app.route("/export_malicious")
def export_malicious():
    # Use combined logic: VT > 50 OR AbuseIP >= 75
    malicious = []
    for r in scan_status["results"]:
        is_mal = False
        vt = r["VT Engine %"]
        abuse = r["AbuseIP %"]

        if vt not in ("ERROR", "QUOTA", "RATE_LIMITED"):
            if float(vt) > 50:
                is_mal = True

        if abuse not in ("ERROR", "QUOTA", "RATE_LIMITED"):
            if float(abuse) >= 75:
                is_mal = True

        if is_mal:
            malicious.append(r)

    if not malicious:
        return jsonify({"status": "no_malicious_found"})

    with open(MALICIOUS_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["S.No", "IP", "AbuseIP %", "VT Engine %"]
        )
        writer.writeheader()
        writer.writerows(malicious)

    return send_file(MALICIOUS_FILE, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)