# Automated IP INVESTIGATE - Project Documentation

## Overview
Automated IP INVESTIGATE is a "Live Threat Monitoring & Risk Analysis Protocol" designed to extract and analyze IP addresses and Hashes (MD5/SHA1/SHA256) from user-uploaded text files. It cross-references these entities against renowned threat intelligence sources—specifically **VirusTotal** and **AbuseIPDB**—to determine their maliciousness.

The application features a dark, cyber-themed UI, real-time scanning progress tracking, interactive 3D visualizations, and an intelligent backend that handles API key rotation and caching.

---

## System Architecture

The project consists of a full-stack architecture:

1. **Backend (Python / Flask):**
   - Serves the frontend application.
   - Parses uploaded files to extract actionable entities (IPs and Hashes) while ignoring private IPs.
   - Handles multi-threaded background processing to query external APIs without blocking the main event loop.
   - Manages API rate-limiting via a custom Key Rotation mechanism.
   - Maintains a local JSON cache to minimize redundant external API calls.

2. **Frontend (HTML / CSS / JavaScript / ECharts):**
   - A single-page application (SPA) interface.
   - Provides controls to Import & Scan files, Terminate running scans, and Export malicious findings to CSV.
   - Displays real-time scan progress and a synthetic "terminal log" feed.
   - Contains interactive ECharts components for visual analysis (3D Threat Topology and a Threat Summary Donut chart).
   - Renders an interactive, filterable, and searchable table of scan results.

---

## Core Components & Logic (Backend - `app.py`)

### 1. Environment & API Key Management
The application uses `python-dotenv` to load environment variables from a `.env` file. It supports both single keys and comma-separated lists of keys for **VirusTotal** (`VT_API_KEYS`) and **AbuseIPDB** (`ABUSE_API_KEYS`).

### 2. Custom API Key Rotator (`KeyRotator` Class)
Since free tier threat intel APIs often have strict rate limits, the `KeyRotator` class intelligently distributes requests across multiple provided keys.
- **Features:** Tracks daily usage limits and per-minute rate limits. Automatically marks a key as "exhausted" if limits are reached or a `429 Too Many Requests` status code is returned.
- **Concurrency Setup:** Uses `threading.Lock()` to ensure thread-safe key retrieval across asynchronous scanning workers.

### 3. Local Caching
To save API quota, the system implements a local file-based cache (`ip_cache.json`). Before querying external services, the app checks if the entity has already been investigated.

### 4. Entity Extraction (`extract_entities` Function)
When a user uploads a file, the system dynamically assesses its format:
- **CSV Parsing:** If a `.csv` file is uploaded, it is natively parsed using Python's `csv` module, preserving all column structure and natively determining active source/destination columns natively (`src` / `dst`).
- **Structured Log Parsing:** If a typical unstructured text file contains tabular headers (e.g., standard Fortigate log format separating columns by tabs/spaces), the script detects this and maps parameters (like `agent.name`, `data.app`, `data.action`) contextually to a `log_context` object.
- **Regex Extraction:** Using regular expressions, the script pulls matching IPv4 addresses (excluding private blocks) and prevalent Hashes (MD5/SHA1/SHA256).
- **Embedded Comments:** Comments located inside parentheses `(Like This)` are dynamically extracted directly from the raw log lines to group related contextual vectors in the table.

### 5. Threat Intelligence Integration
- **Virustotal API (v3):** Function `vt_lookup` (for Hashes) and `vt_ip_lookup` (for IPs). Extracts the `last_analysis_stats` to compute a percentage score based on vendors flagging the entity as malicious.
- **AbuseIPDB API (v2):** Function `abuse_lookup`. Retrieves the `abuseConfidenceScore` and other contextual OSINT like ISP, domain, and total reports.

### 6. Background Processing & Threading
When a scan is initiated:
1. The global `scan_status` state is initialized (Thread-safe via `scan_lock`).
2. A separate background thread (`background_scan`) is spun up.
3. It utilizes a `ThreadPoolExecutor` (max 3 workers) to process extracted entities concurrently by calling `process_entity`.

---

## API Endpoints

- `GET /` : Serves the main UI.
- `POST /start_scan` : Accepts a file upload (`multipart/form-data`), extracts vectors, and kicks off the background thread if vectors exist.
- `GET /progress` (or `/scan_status`) : Returns JSON containing the current global state (total targets, completed targets, active results array). Polled by the frontend.
- `POST /stop_scan` : Flags the background process to abort gracefully.
- `GET /api_status` : Returns the sum of remaining available queries for loaded API keys.
- `GET /export_malicious` : Filters the completed scan results for malicious thresholds (VT > 50% or AbuseIPDB >= 75%), generates a CSV (`malicious_only.csv`), and sends it back as a downloadable attachment.

---

## Frontend Logic (`index.html` & `style.css`)

### User Interface & Theming
- Styled with CSS variables mimicking a "Cyber / Hacker" aesthetic (Neon Blue, Red, Green against a Dark background).
- Uses a background css grid pattern (`.bg-grid`).

### Real-Time Interactions (JavaScript)
- **Polling Mechanism:** When scanning starts, `setInterval` triggers requests to `/progress` every 1000ms.
- **Terminal Animation:** As new results stream in, the frontend synthesizes a "terminal feed" updating the user on entity verdicts.
- **Result Processing:** Data returned via `/progress` is parsed to update:
  1. The master table (with nested `<tr>` generation for interactive groups and comments).
  2. Summary cards (Malicious, Suspicious, Clean, Error).
  3. Interactive Echarts.

### Interactive Components
- **Advanced Table Fields:** The dashboard calculates the exact Geographic Country directly in the primary table row. If the intelligence detects the IP as originating from a recognizable header (e.g. `srcip`), it annotates the row with contextual flags (`[SRC]` or `[DST]`).
- **Expandable Rows & Log Context:** Malicious and Suspicious entities in the table can be expanded by clicking the Info icon (ⓘ) or arrow (➜). This reveals detailed OSINT components dynamically assembled via JavaScript (e.g., ISP, ASN, Last Seen Date). Additionally, any extended contextual rows from uploaded `.csv`s or parsed firewall logs (like Port Numbers, App Rules, Log Actions) are rendered in a sleek `LOG_CONTEXT_EXTRACT` panel directly inside the row summary.
- **Visualizations:**
  - **3D Topology Chart:** Uses ECharts-GL to plot a 3D bar surface representation of threat scores, helping visually spot density of risky IPs.
  - **Summary Donut:** A simple pie chart mapping the aggregate proportions of Threat statuses.

---

## Helper Scripts
- `ip-scan.py`: A simple/legacy CLI script to demonstrate basic ip polling against a free `ip-api.com` endpoint.

## Setup Requirements

Refer to `requirements.txt` for dependencies:
```text
Flask==2.3.3
requests==2.31.0
python-dotenv==1.0.0
gunicorn==21.2.0
```

1. Install Python packages: `pip install -r requirements.txt`
2. Configure `.env` with `VT_API_KEYS` and `ABUSE_API_KEYS`.
3. Run `python app.py`. Use modern browsers compatible with WebGL (for ECharts 3D) on `http://127.0.0.1:5000`.
