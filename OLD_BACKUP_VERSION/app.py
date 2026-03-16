from flask import Flask, render_template, request, redirect, send_file
import requests
import ipaddress
import csv
import os
import re
import time

app = Flask(__name__)

RESULT_FILE = "all_results.csv"
MALICIOUS_FILE = "malicious_only.csv"

VT_API_KEY = "PUT_YOUR_VT_KEY_HERE"
ABUSE_API_KEY = "PUT_YOUR_ABUSE_KEY_HERE"

# -----------------------------
# Extract IPs
# -----------------------------
def extract_ips(text):
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    return list(dict.fromkeys(ips))

# -----------------------------
# VirusTotal
# -----------------------------
def vt_lookup(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}

    r = requests.get(url, headers=headers)

    if r.status_code != 200:
        print("VT Error:", r.text)
        return "ERROR"

    data = r.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]

    total = sum(stats.values())
    malicious = stats.get("malicious", 0)

    if total == 0:
        return 0

    return round((malicious / total) * 100, 2)

# -----------------------------
# AbuseIPDB
# -----------------------------
def abuse_lookup(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    r = requests.get(url, headers=headers, params=params)

    if r.status_code == 200:
        return r.json()["data"]["abuseConfidenceScore"]

    print("Abuse Error:", r.text)
    return "ERROR"

# -----------------------------
# MAIN ROUTE
# -----------------------------
@app.route("/", methods=["GET", "POST"])
def dashboard():

    if request.method == "POST":
        file = request.files.get("file")

        if not file:
            return redirect("/")

        content = file.read().decode("utf-8")
        ips = extract_ips(content)

        # CLEAR OLD RESULTS
        with open(RESULT_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["S.No", "IP", "AbuseIP %", "VT Engine %"])

        serial = 1

        for ip in ips:
            try:
                if ipaddress.ip_address(ip).is_private:
                    continue
            except:
                continue

            print("Scanning:", ip)

            abuse = abuse_lookup(ip)
            vt = vt_lookup(ip)

            with open(RESULT_FILE, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([serial, ip, abuse, vt])

            serial += 1
            time.sleep(0.5)  # avoid API rate limit

        return redirect("/")

    results = []
    if os.path.exists(RESULT_FILE):
        with open(RESULT_FILE, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            results = list(reader)

    return render_template("index.html", results=results)

# -----------------------------
# EXPORT MALICIOUS
# -----------------------------
@app.route("/export_malicious")
def export_malicious():

    if not os.path.exists(RESULT_FILE):
        return redirect("/")

    with open(RESULT_FILE, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    malicious = [r for r in rows if str(r["VT Engine %"]) != "ERROR" and float(r["VT Engine %"]) > 50]

    with open(MALICIOUS_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["S.No", "IP", "AbuseIP %", "VT Engine %"])
        writer.writeheader()
        writer.writerows(malicious)

    return send_file(MALICIOUS_FILE, as_attachment=True)

if __name__ == "__main__":
    print("Starting Clean Cyber Tool")
    app.run(debug=True)
