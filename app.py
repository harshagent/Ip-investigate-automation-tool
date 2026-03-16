from flask import Flask, render_template, request, jsonify, send_file
import requests
import ipaddress
import re
import threading
import csv
import os
import time
import json
import io
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed

# -----------------------------
# LOAD ENV
# -----------------------------
load_dotenv()

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

print(f"✅ [SESSION_{int(time.time())}] Loaded {len(VT_API_KEYS)} VT key(s), {len(ABUSE_API_KEYS)} AbuseIPDB key(s)", flush=True)

app = Flask(__name__)

MALICIOUS_FILE = "malicious_only.csv"
CACHE_FILE = "ip_cache.json"

# -----------------------------
# API KEY ROTATOR
# -----------------------------
class KeyRotator:
    def __init__(self, keys, daily_limit, per_minute_limit=None):
        self.keys = keys
        self.daily_limit = daily_limit
        self.per_minute_limit = per_minute_limit
        self.index = 0
        self.usage = {k: {"daily": 0, "minute_ts": [], "exhausted": False} for k in keys}
        self.lock = threading.Lock()

    def get_key(self):
        with self.lock:
            attempts = 0
            while attempts < len(self.keys):
                key = self.keys[self.index]
                self.index = (self.index + 1) % len(self.keys)
                info = self.usage[key]
                if info["exhausted"]:
                    attempts += 1
                    continue
                if info["daily"] >= self.daily_limit:
                    info["exhausted"] = True
                    attempts += 1
                    continue
                if self.per_minute_limit:
                    now = time.time()
                    info["minute_ts"] = [t for t in info["minute_ts"] if now - t < 60]
                    if len(info["minute_ts"]) >= self.per_minute_limit:
                        attempts += 1
                        continue
                info["daily"] += 1
                if self.per_minute_limit:
                    info["minute_ts"].append(time.time())
                return key
            return None

    def mark_exhausted(self, key):
        with self.lock:
            if key in self.usage:
                self.usage[key]["exhausted"] = True

    def total_remaining(self):
        with self.lock:
            return sum(max(0, self.daily_limit - self.usage[k]["daily"]) for k in self.keys)

vt_rotator = KeyRotator(VT_API_KEYS, daily_limit=500, per_minute_limit=4)
abuse_rotator = KeyRotator(ABUSE_API_KEYS, daily_limit=1000)

# -----------------------------
# LOCAL CACHE
# -----------------------------
ip_cache = {}
cache_lock = threading.Lock()

def load_cache():
    global ip_cache
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                ip_cache = json.load(f)
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
# Entity Extraction
# -----------------------------
def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def extract_entities(text, filename=""):
    """Extract IPs, Hashes, Comments, Context and Separators from input text/csv."""
    entities = []
    group_idx = 1
    
    # If it's a CSV, try parsing it as one
    if filename.endswith(".csv"):
        f = io.StringIO(text)
        try:
            reader = csv.DictReader(f)
            if reader.fieldnames:
                for row_idx, row in enumerate(reader):
                    row_context = {k: v for k, v in row.items() if v and str(v).strip()}
                    found_ip = False
                    for key, val in row.items():
                        if not val: continue
                        val_str = str(val).strip()
                        
                        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', val_str)
                        if ip_match:
                            ip = ip_match.group(0)
                            if not is_private_ip(ip):
                                direction = "Source" if "src" in str(key).lower() or "source" in str(key).lower() else \
                                            "Target" if "dst" in str(key).lower() or "dest" in str(key).lower() else "Unknown"
                                entities.append({
                                    "type": "ip", "value": ip, "comment": f"Row {row_idx+1}",
                                    "group": group_idx, "direction": direction, "log_context": row_context
                                })
                                found_ip = True
                                
                        hash_match = re.search(r'\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b', val_str)
                        if hash_match:
                            entities.append({
                                "type": "hash", "value": hash_match.group(0), "comment": f"Row {row_idx+1}",
                                "group": group_idx, "direction": "N/A", "log_context": row_context
                            })
                            found_ip = True
                    if found_ip: group_idx += 1
                return entities
        except Exception as e:
            print(f"CSV Parse error: {e}")

    lines = text.splitlines()
    is_table_like = False
    headers = []
    if len(lines) > 0 and ("srcip" in lines[0].lower() or "source" in lines[0].lower() or "agent.name" in lines[0].lower()):
        is_table_like = True
        headers = re.split(r'\t| {2,}', lines[0].strip())

    for line_idx, line in enumerate(lines):
        line = line.strip()
        if not line: continue
        if line.startswith("---"):
            group_idx += 1
            entities.append({"type": "separator", "group": group_idx})
            continue

        # Find comment on the original line before column logic
        comment_match = re.search(r'\((.*?)\)', line)
        comment = comment_match.group(1) if comment_match else None
        clean_line = re.sub(r'\(.*?\)', '', line).strip()
        
        if is_table_like and line_idx == 0: continue

        log_context = {}
        if is_table_like:
            cols = re.split(r'\t| {2,}', clean_line)
            for i, col in enumerate(cols):
                if i < len(headers): log_context[headers[i]] = col.strip()
        else:
            log_context = {"raw_log": clean_line}

        found = False
        for ip_match in re.finditer(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', clean_line):
            ip = ip_match.group(0)
            if not is_private_ip(ip):
                direction = "Unknown"
                if is_table_like:
                    for k, v in log_context.items():
                        if ip in v:
                            if "src" in k.lower() or "source" in k.lower(): direction = "Source"
                            elif "dst" in k.lower() or "dest" in k.lower(): direction = "Target"
                entities.append({
                    "type": "ip", "value": ip, "comment": comment, 
                    "group": group_idx, "direction": direction, "log_context": log_context
                })
                found = True

        for hash_match in re.finditer(r'\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b', clean_line):
             entities.append({
                "type": "hash", "value": hash_match.group(0), "comment": comment, 
                "group": group_idx, "direction": "N/A", "log_context": log_context
            })
             found = True
             
        if found and is_table_like: group_idx += 1

    return entities

# -----------------------------
# VIRUSTOTAL (Hashes only)
# -----------------------------
def vt_lookup(resource, rtype, attempt=0):
    if rtype != "hash":
        return {"result": "Not Hash"}

    if attempt >= len(VT_API_KEYS):
        return {"result": "QUOTA"}

    with cache_lock:
        if resource in ip_cache and "vt_details" in ip_cache[resource]:
            return ip_cache[resource]["vt_details"]

    key = vt_rotator.get_key()
    if key is None:
        return {"result": "QUOTA"}

    try:
        url = f"https://www.virustotal.com/api/v3/files/{resource}"
        headers = {"x-apikey": key}
        r = requests.get(url, headers=headers, timeout=15)

        if r.status_code == 429:
            vt_rotator.mark_exhausted(key)
            return vt_lookup(resource, rtype, attempt + 1)
        
        if r.status_code == 404:
            return {"result": "Clean (Not Found)"}

        if r.status_code != 200:
            return {"result": "ERROR"}

        data = r.json()["data"]["attributes"]
        stats = data["last_analysis_stats"]
        total = sum(stats.values())
        malicious = stats.get("malicious", 0)
        score = round((malicious / total) * 100, 2) if total else 0

        details = {
            "result": score,
            "stats": stats,
            "last_analysis_date": data.get("last_analysis_date"),
            "times_submitted": data.get("times_submitted"),
            "meaningful_name": data.get("meaningful_name")
        }

        with cache_lock:
            if resource not in ip_cache: ip_cache[resource] = {}
            ip_cache[resource]["vt_details"] = details
            ip_cache[resource]["vt"] = score # Keep for compat
        return details
    except Exception:
        return {"result": "ERROR"}

def vt_ip_lookup(ip, attempt=0):
    if attempt >= len(VT_API_KEYS):
        return None

    with cache_lock:
        if ip in ip_cache and "vt_ip_details" in ip_cache[ip]:
            return ip_cache[ip]["vt_ip_details"]

    key = vt_rotator.get_key()
    if key is None: return None

    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": key}
        r = requests.get(url, headers=headers, timeout=15)

        if r.status_code == 429:
            vt_rotator.mark_exhausted(key)
            return vt_ip_lookup(ip, attempt + 1)
        
        if r.status_code != 200: return None

        data = r.json()["data"]["attributes"]
        stats = data["last_analysis_stats"]
        
        details = {
            "stats": stats,
            "reputation": data.get("reputation"),
            "asn": data.get("asn"),
            "as_owner": data.get("as_owner"),
            "country": data.get("country")
        }

        with cache_lock:
            if ip not in ip_cache: ip_cache[ip] = {}
            ip_cache[ip]["vt_ip_details"] = details
        return details
    except Exception:
        return None

# -----------------------------
# ABUSEIPDB (IPs only)
# -----------------------------
def abuse_lookup(ip, rtype, attempt=0):
    if rtype != "ip":
        return {"score": 0, "status": "Not IP"}

    if attempt >= len(ABUSE_API_KEYS):
        return {"score": 0, "status": "QUOTA"}

    with cache_lock:
        if ip in ip_cache and "abuse_details" in ip_cache[ip]:
            return ip_cache[ip]["abuse_details"]
        elif ip in ip_cache and "abuse" in ip_cache[ip]:
            # Legacy cache migration
            return {"score": ip_cache[ip]["abuse"], "status": "legacy"}

    key = abuse_rotator.get_key()
    if key is None:
        return {"score": 0, "status": "QUOTA"}

    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
        r = requests.get(url, headers=headers, params=params, timeout=15)

        if r.status_code == 429:
            abuse_rotator.mark_exhausted(key)
            return abuse_lookup(ip, rtype, attempt + 1)

        if r.status_code == 200:
            data = r.json()["data"]
            details = {
                "score": data.get("abuseConfidenceScore", 0),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "country": data.get("countryName"),
                "usage_type": data.get("usageType"),
                "total_reports": data.get("totalReports"),
                "last_reported": data.get("lastReportedAt"),
                "status": "success"
            }
            with cache_lock:
                if ip not in ip_cache: ip_cache[ip] = {}
                ip_cache[ip]["abuse_details"] = details
                ip_cache[ip]["abuse"] = details["score"] # Compat
            return details
            return details
        return {"score": 0, "status": "ERROR"}
    except Exception as e:
        print(f"DEBUG: AbuseLookup Exception: {e}", flush=True)
        return {"score": 0, "status": "ERROR"}

# -----------------------------
# GEO IP LOOKUP (ip-api.com)
# -----------------------------
def geo_lookup(ip, attempt=0):
    if attempt > 2:
        return None
        
    with cache_lock:
        if ip in ip_cache and "geo_data" in ip_cache[ip]:
            return ip_cache[ip]["geo_data"]
            
    try:
        url = f"http://ip-api.com/json/{ip}"
        # ip-api allows 45 req/min. If we hit 429, backoff
        r = requests.get(url, timeout=5)
        if r.status_code == 429:
            time.sleep(2)
            return geo_lookup(ip, attempt + 1)
            
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                geo_info = {
                    "country": data.get("country", "Unknown"),
                    "lat": data.get("lat", 0.0),
                    "lon": data.get("lon", 0.0)
                }
                with cache_lock:
                    if ip not in ip_cache: ip_cache[ip] = {}
                    ip_cache[ip]["geo_data"] = geo_info
                return geo_info
    except Exception as e:
        print(f"DEBUG: GeoLookup Exception: {e}", flush=True)
    return None

# -----------------------------
# Process Entity
# -----------------------------
def process_entity(entity, serial):
    if scan_status["stop_requested"]:
        return None
    
    rtype = entity["type"]
    val = entity["value"]
    
    try:
        time.sleep(0.3)
        abuse_out = abuse_lookup(val, rtype)
        vt_out = vt_lookup(val, rtype)
        
        vt_res = vt_out if isinstance(vt_out, dict) else {"result": vt_out}
        
        geo_data = None
        if rtype == "ip":
            geo_data = geo_lookup(val)
        
        # Merge Intelligence
        intel_payload = {
            "vt": vt_res if rtype == "hash" else vt_ip_lookup(val),
            "abuse": abuse_out if rtype == "ip" else None
        }

        # Calculate result scores for table compat
        abuse_score = abuse_out.get("score") if isinstance(abuse_out, dict) else abuse_out
        vt_score = vt_res.get("result")

        return {
            "S.No": serial,
            "Target": val,
            "Type": rtype,
            "Comment": entity.get("comment"),
            "Group": entity.get("group"),
            "Direction": entity.get("direction", "Unknown"),
            "Log_Context": entity.get("log_context", {}),
            "AbuseIP %": abuse_score,
            "VT Engine %": vt_score,
            "VT_Details": intel_payload["vt"], # For legacy JS logic
            "Abuse_Details": intel_payload["abuse"], # NEW: For enhanced panels
            "Geo_Data": geo_data,
            "IP": val 
        }
    except Exception as e:
        print(f"ERROR processing {val}: {e}")
        return {
            "S.No": serial,
            "Target": val,
            "Type": rtype,
            "Comment": entity.get("comment"),
            "Group": entity.get("group"),
            "Direction": entity.get("direction", "Unknown"),
            "Log_Context": entity.get("log_context", {}),
            "AbuseIP %": "ERROR",
            "VT Engine %": "ERROR",
            "VT_Details": {},
            "Abuse_Details": {},
            "Geo_Data": None,
            "IP": val
        }

# -----------------------------
# Background Scan
# -----------------------------
def background_scan():
    print("ULTRA-VERBOSE: background_scan THREAD COMMENCING...", flush=True)
    try:
        with scan_lock:
            scan_targets = scan_status["targets"]
            scan_status["running"] = True
            total = len(scan_targets)
        
        print(f"ULTRA-VERBOSE: Background scan started for {total} targets.", flush=True)
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            print("ULTRA-VERBOSE: Executor initialized. Submitting tasks...", flush=True)
            futures = {
                executor.submit(process_entity, target, i + 1): target
                for i, target in enumerate(scan_targets)
            }
            print(f"ULTRA-VERBOSE: {len(futures)} tasks submitted to executor.", flush=True)

            for future in as_completed(futures):
                if scan_status["stop_requested"]:
                    print("ULTRA-VERBOSE: Stop requested. Aborting loop.", flush=True)
                    break
                try:
                    result = future.result()
                    with scan_lock:
                        if result:
                            scan_status["results"].append(result)
                        scan_status["completed"] += 1
                        completed = scan_status["completed"]
                    print(f"ULTRA-VERBOSE: Task result acquired ({completed}/{total}). Result present: {result is not None}", flush=True)
                except Exception as e:
                    print(f"ULTRA-VERBOSE: TASK CRITICAL FAILURE: {e}", flush=True)
                    with scan_lock:
                        scan_status["completed"] += 1
    except Exception as outer_e:
        print(f"ULTRA-VERBOSE: BACKGROUND THREAD FATAL ERROR: {outer_e}", flush=True)
    finally:
        save_cache()
        with scan_lock:
            scan_status["running"] = False
        print("ULTRA-VERBOSE: background_scan THREAD TERMINATED SAFELY.", flush=True)

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

    filename = file.filename.lower()
    content = file.read().decode("utf-8", errors="ignore")
    entities = extract_entities(content, filename)
    scan_targets = [e for e in entities if e.get("type") != "separator"]

    if not scan_targets:
        return jsonify({"status": "no_vectors_found"})

    with scan_lock:
        scan_status["total"] = len(scan_targets)
        scan_status["completed"] = 0
        scan_status["results"] = []
        scan_status["running"] = True
        scan_status["targets"] = scan_targets
        scan_status["stop_requested"] = False
    
    print(f"DEBUG: Scan started for {len(scan_targets)} targets.", flush=True)
    thread = threading.Thread(target=background_scan, daemon=True)
    thread.start()

    return jsonify({
        "status": "started",
        "total_ips": len(scan_targets),
        "vt_keys": len(VT_API_KEYS),
        "abuse_keys": len(ABUSE_API_KEYS),
        "cached_ips": len(ip_cache)
    })

@app.route("/progress")
@app.route("/scan_status")
def progress():
    with scan_lock:
        # Create a safe copy of the status for serialization
        status_copy = {
            "total": scan_status["total"],
            "completed": scan_status["completed"],
            "running": scan_status["running"],
            "stop_requested": scan_status["stop_requested"],
            "results": list(scan_status["results"]) # Copy the list of results
        }
    return jsonify(status_copy)

@app.route("/stop_scan", methods=["POST"])
def stop_scan():
    scan_status["stop_requested"] = True
    return jsonify({"status": "stopping"})

@app.route("/api_status")
def api_status():
    return jsonify({
        "vt_remaining": vt_rotator.total_remaining(),
        "abuse_remaining": abuse_rotator.total_remaining(),
        "cached_ips": len(ip_cache)
    })

@app.route("/export_malicious")
def export_malicious():
    malicious = []
    for r in scan_status["results"]:
        is_mal = False
        vt = r["VT Engine %"]
        abuse = r["AbuseIP %"]
        
        if isinstance(vt, (int, float)) and vt > 50:
            is_mal = True
        if isinstance(abuse, (int, float)) and abuse >= 75:
            is_mal = True

        if is_mal:
            malicious.append(r)

    if not malicious:
        return jsonify({"status": "no_malicious_found"})

    with open(MALICIOUS_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["S.No", "Target", "Type", "Comment", "Group", "AbuseIP %", "VT Engine %"],
            extrasaction='ignore'
        )
        writer.writeheader()
        writer.writerows(malicious)

    return send_file(MALICIOUS_FILE, as_attachment=True)

if __name__ == "__main__":
    try:
        port = int(os.environ.get("PORT", 5000))
        app.run(host='0.0.0.0', port=port, debug=True)
    except Exception as e:
        print(f"CRITICAL: Server crashed on startup: {e}")
