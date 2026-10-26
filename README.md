# NetScope — IPv4 Network Analysis & Anomaly Investigation

A local Flask + JavaScript application for analysing packet-level CSV data, building IPv4 host/flow summaries, ranking unusual traffic with robust statistics and Isolation Forest, exploring host relationships, and exporting evidence-linked findings.

## Features
- CSV upload, schema alias recognition, input validation and data-quality summary.
- Dedicated CSV Analysis tab with dataset profile, protocol shares, source/destination traffic rankings, data-quality results, detector summary, top findings, and downloadable analysis-summary CSV.
- IPv4 host classification (private/public/loopback/link-local/reserved), protocol and port analysis.
- Host inventory, top talkers, flow construction, and interactive topology graph.
- Robust MAD/Z-score outlier checks, Isolation Forest on flow features (when at least 20 flows), and a supporting destination-port-diversity rule.
- Alert explanations linked to flow IDs and source row IDs.
- CSV exports for hosts, flows and alerts, plus a JSON investigation report.
- Synthetic demo dataset for repeatable presentation.
- Optional short live capture with Scapy. Requires authorised monitoring, Npcap on Windows, suitable permissions and compatible interface.

## Requirements
- Windows 10/11 with Python 3.10+.
- Internet connection for the first installation (to install Python packages).
- For live capture only: Npcap installed, supported adapter, and PowerShell run as Administrator. CSV/demo analysis does not require administrator permissions.

## Run on Windows PowerShell
1. Extract the ZIP into a new folder, for example `C:\Users\<you>\Downloads\NetScope_New_Project`.
2. Open PowerShell and move into the project folder:
   ```powershell
   cd "C:\Users\<you>\Downloads\NetScope_New_Project"
   ```
3. Create a virtual environment:
   ```powershell
   py -3 -m venv .venv
   ```
4. Install packages without activating the environment (avoids PowerShell execution-policy issues):
   ```powershell
   .\.venv\Scripts\python.exe -m pip install --upgrade pip
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   ```
5. Start the server:
   ```powershell
   .\.venv\Scripts\python.exe app.py
   ```
6. Open **http://127.0.0.1:5001** in your browser. Keep the PowerShell window open while using the app.
7. Stop the server with `Ctrl+C`.

## How to demonstrate
1. Open the app and choose **Load demo data**.
2. Show IPv4/data-quality metrics, protocol distribution, host inventory and topology.
3. Open the **Detection Lab** section and review alerts, algorithm names and explanations.
4. Upload a CSV. Recommended packet-level columns include `timestamp, source_ip, destination_ip, transport_protocol, ip_length, source_port, destination_port, ttl, src_mac, dst_mac`. Common aliases such as `src`, `dst`, `proto`, `sport`, `dport`, `length`, `time`, `src_mac`, and `dst_mac` are recognised.
5. Open **CSV Analysis** to review the imported dataset profile, protocol breakdown, top source/destination endpoints, quality checks, active detector thresholds and highest-scoring findings.
6. Use **Export analysis summary CSV** to download a compact, evidence-oriented summary. This is separate from exporting the raw flows CSV; exporting does not automatically re-import or re-analyse the downloaded file.

## CSV behaviour and limits
- Maximum upload: 10 MB and 100,000 rows.
- The importer supports packet-level data and some flow-feature CSVs with mapped aliases. A flow-feature dataset cannot recreate packet-level fields that it did not record.
- Invalid or non-IPv4 source/destination rows are counted and excluded from IPv4-specific aggregates when valid records exist.
- Checksum status is summarised if the CSV provides a checksum-status column. Actual IPv4 header checksum verification requires raw header bytes; ordinary summary CSVs do not contain enough information to recompute it.
- TLS payload content is not decrypted or inspected.
- Alerts indicate unusual behaviour, not confirmed malicious activity.
- The default detector is unsupervised and not trained on labelled attacks. Evaluation metrics such as precision/recall require trustworthy ground-truth labels.

## Optional live capture
The live capture button is disabled/unavailable if Scapy cannot load. Install Npcap from its official site, then:
```powershell
.\.venv\Scripts\python.exe -m pip install scapy
```
Run PowerShell as Administrator and use only interfaces/networks you are authorised to monitor. Some adapters/drivers do not expose all traffic.

## Project structure
- `app.py` — Flask routes, CSV upload, capture API and exports.
- `net_analysis.py` — normalisation, IPv4 checks, flow/host summaries, anomaly detectors and report generation.
- `capture.py` — optional Scapy packet capture adapter.
- `templates/index.html` — application layout, including CSV Analysis workspace.
- `static/css/style.css` — dashboard styling.
- `static/js/app.js` — frontend interactions, API requests, chart rendering, filters, and CSV-analysis report rendering.
- `requirements.txt` — Python dependencies.
- `uploads/` — reserved for local uploads (not committed with user data).

## Privacy and safety
Only capture traffic you have permission to monitor. Avoid collecting payloads or credentials. Uploaded CSVs are analysed in memory; do not upload sensitive production data into a shared environment.


## Continuous live packet capture (Windows)

The dashboard supports continuous capture in addition to demo and CSV analysis. Install the Python dependencies and install **Npcap** from its official website. During Npcap setup, enable WinPcap API-compatible mode if offered. Run PowerShell as Administrator if your adapter requires elevated capture privileges. Start NetScope, choose a listed adapter (the default option lets Scapy choose), then click **Start live capture**. Generate ordinary network activity such as opening a website; the dashboard polls the backend and refreshes packet metrics, flows, hosts, charts and anomaly findings approximately every 1.5 seconds. Click **Stop capture** when finished.

If the capture button is disabled, verify that Scapy installed in the same `.venv` used to run `app.py`. If capture returns an access/driver error, install/reinstall Npcap and restart PowerShell as Administrator. The loopback adapter only sees loopback traffic; choose the Wi-Fi or Ethernet adapter to monitor that interface. Packet capture should only be used on networks you are authorised to monitor.

## Live capture and detection thresholds

The dashboard header lets you choose Demo data or Live capture, select a detected Scapy interface, and start, pause/resume, or stop capture. Live capture on Windows generally requires Npcap and appropriate permissions; run PowerShell as Administrator if the adapter requires it. Choose the Wi-Fi/Ethernet adapter for network traffic; loopback only observes loopback traffic.

The Detection Lab includes backend-applied thresholds, editable while the app is running:
- Robust Z-score threshold (default 3.0; accepted range 1–10)
- Unique destination ports per source (default 8; accepted range 2–65535)
- Packets per source in the analysed dataset (default 100; accepted range 1–1,000,000)

Click **Save thresholds & re-analyse** to apply these values to the currently loaded data. These are heuristic investigation rules, not proof of an attack. The packet-volume threshold is calculated across the current analysed/retained dataset, not a strict sliding 10-second window.
