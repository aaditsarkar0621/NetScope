from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
from pathlib import Path
import pandas as pd
import json, io, time, hashlib, os, traceback
from datetime import datetime, timezone
from net_analysis import analyze_dataframe, make_demo_data, normalize_dataframe, build_report
from capture import capture_available, list_interfaces, capture_packets, start_capture, stop_capture, capture_status, captured_records, pause_capture

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = str(Path(__file__).parent / "uploads")
Path(app.config["UPLOAD_FOLDER"]).mkdir(exist_ok=True)
THRESHOLDS = {"robust_z": 3.0, "unique_ports": 8, "source_packets": 100}
STATE = {"data": None, "analysis": None, "source": "Demo data", "filename": "demo.csv", "imported_at": None}

def current_payload():
    if STATE["analysis"] is None:
        df = make_demo_data()
        STATE["data"] = df
        STATE["analysis"] = analyze_dataframe(df, thresholds=THRESHOLDS)
        STATE["source"] = "Synthetic demo data"
        STATE["filename"] = "demo.csv"
        STATE["imported_at"] = datetime.now(timezone.utc).isoformat()
    STATE["analysis"].setdefault("provenance", {})["thresholds"] = dict(THRESHOLDS)
    return STATE["analysis"]

@app.get("/")
def index():
    current_payload()
    return render_template("index.html", capture_available=capture_available())

@app.get("/api/health")
def health():
    return jsonify({"status":"ok", "application":"NetScope", "capture_available":capture_available()})

@app.get("/api/analytics")
def analytics():
    return jsonify(current_payload())

@app.post("/api/demo")
def demo():
    df = make_demo_data()
    STATE.update(data=df, analysis=analyze_dataframe(df, thresholds=THRESHOLDS), source="Synthetic demo data", filename="demo.csv",
                 imported_at=datetime.now(timezone.utc).isoformat())
    return jsonify(STATE["analysis"])


@app.get("/api/capture/status")
def live_capture_status():
    status = capture_status()
    return jsonify({"available": capture_available(), "status": status, "interfaces": list_interfaces()})

@app.post("/api/capture/start")
def live_capture_start():
    body = request.get_json(silent=True) or {}
    interface = body.get("interface") or None
    available = list_interfaces()
    if interface and interface not in available:
        return jsonify(error="That interface is not in the detected interface list. Refresh and select a listed interface."), 400
    try:
        status = start_capture(interface)
        return jsonify({"status": status, "message": "Live capture started. Generate network activity to see packets arrive."})
    except Exception as exc:
        app.logger.exception("Could not start live capture")
        return jsonify(error=str(exc)), 400

@app.post("/api/capture/stop")
def live_capture_stop():
    return jsonify({"status": stop_capture()})

@app.post("/api/capture/pause")
def live_capture_pause():
    body = request.get_json(silent=True) or {}
    try:
        return jsonify({"status": pause_capture(bool(body.get("paused", True)))})
    except Exception as exc:
        return jsonify(error=str(exc)), 400

@app.get("/api/thresholds")
def get_thresholds():
    return jsonify(THRESHOLDS)

@app.post("/api/thresholds")
def set_thresholds():
    body = request.get_json(silent=True) or {}
    try:
        values = {"robust_z": float(body.get("robust_z", THRESHOLDS["robust_z"])),
                  "unique_ports": int(body.get("unique_ports", THRESHOLDS["unique_ports"])),
                  "source_packets": int(body.get("source_packets", THRESHOLDS["source_packets"]))}
        if not (1.0 <= values["robust_z"] <= 10.0): raise ValueError("Robust Z threshold must be between 1 and 10.")
        if not (2 <= values["unique_ports"] <= 65535): raise ValueError("Unique destination ports must be between 2 and 65535.")
        if not (1 <= values["source_packets"] <= 1000000): raise ValueError("Source packet threshold must be between 1 and 1,000,000.")
        THRESHOLDS.update(values)
        if STATE.get("data") is not None:
            result, normalized = analyze_dataframe(STATE["data"], return_normalized=True, thresholds=THRESHOLDS)
            result.setdefault("provenance", {})["thresholds"] = dict(THRESHOLDS)
            STATE.update(data=normalized, analysis=result)
            return jsonify({"thresholds": THRESHOLDS, "analysis": result})
        return jsonify({"thresholds": THRESHOLDS})
    except (ValueError, TypeError) as exc:
        return jsonify(error=str(exc)), 400

@app.get("/api/capture/live")
def live_capture_data():
    status = capture_status()
    records = captured_records()
    if records:
        df = pd.DataFrame(records)
        result, normalized = analyze_dataframe(df, return_normalized=True, thresholds=THRESHOLDS)
        result["provenance"].update({"mode":"Live capture", "source":"Live packet capture", "filename":"live packets", "interface":status.get("interface") or "default", "capture_status":"running" if status.get("running") else "stopped", "packets_seen":status.get("packets_seen", len(records))})
        STATE.update(data=normalized, analysis=result, source="Live capture", filename="live packets", imported_at=datetime.now(timezone.utc).isoformat())
    elif status.get("running"):
        empty = pd.DataFrame(columns=["timestamp", "source_ip", "destination_ip", "transport_protocol", "ip_length", "source_port", "destination_port", "ttl", "src_mac", "dst_mac", "ipv4_checksum_status"])
        result = analyze_dataframe(empty, thresholds=THRESHOLDS)
        result["provenance"].update({"mode":"Live capture", "source":"Live capture — waiting for packets", "filename":"live capture (waiting)", "interface":status.get("interface") or "default", "capture_status":"running", "packets_seen":0})
    else:
        result = current_payload()
        result = dict(result)
        result["provenance"] = dict(result.get("provenance", {}))
        result["provenance"].update({"capture_status":"stopped", "capture_error":status.get("error"), "packets_seen":status.get("packets_seen", 0)})
    return jsonify({"status": status, "analysis": result, "record_count": len(records)})

@app.post("/api/analyze/csv")
def analyze_csv():
    if "file" not in request.files:
        return jsonify(error="Choose a CSV file first."), 400
    f = request.files["file"]
    if not f.filename or not f.filename.lower().endswith(".csv"):
        return jsonify(error="Please upload a .csv file."), 400
    raw = f.read()
    if len(raw) > 10 * 1024 * 1024:
        return jsonify(error="CSV exceeds the 10 MB upload limit."), 413
    digest = hashlib.sha256(raw).hexdigest()
    try:
        df = pd.read_csv(io.BytesIO(raw), low_memory=False)
        if df.empty:
            return jsonify(error="The CSV contains no data rows."), 400
        if len(df) > 100000:
            return jsonify(error="Please use a CSV with at most 100,000 rows for this demo build."), 413
        result, normalized = analyze_dataframe(df, return_normalized=True, thresholds=THRESHOLDS)
        result["provenance"].update({"filename":secure_filename(f.filename), "sha256":digest})
        STATE.update(data=normalized, analysis=result, source="Imported CSV", filename=secure_filename(f.filename),
                     imported_at=datetime.now(timezone.utc).isoformat())
        return jsonify(result)
    except Exception as exc:
        app.logger.exception("CSV analysis failed")
        return jsonify(error=f"Could not analyze CSV: {exc}"), 400

@app.get("/api/interfaces")
def interfaces():
    return jsonify({"available":capture_available(), "interfaces":list_interfaces()})

@app.post("/api/capture")
def capture():
    body = request.get_json(silent=True) or {}
    seconds = max(2, min(int(body.get("seconds", 8)), 20))
    interface = body.get("interface") or None
    try:
        records = capture_packets(seconds, interface)
        if not records:
            return jsonify(error="No packets were captured. Check permissions, interface selection, and capture driver."), 400
        df = pd.DataFrame(records)
        result, normalized = analyze_dataframe(df, return_normalized=True, thresholds=THRESHOLDS)
        result["provenance"].update({"mode":"Live capture", "capture_seconds":seconds, "interface":interface or "default"})
        STATE.update(data=normalized, analysis=result, source="Live capture", filename="live-capture",
                     imported_at=datetime.now(timezone.utc).isoformat())
        return jsonify(result)
    except Exception as exc:
        return jsonify(error=str(exc)), 400

@app.get("/api/export/<kind>")
def export(kind):
    result = current_payload()
    if kind == "alerts":
        content = pd.DataFrame(result.get("alerts", [])).to_csv(index=False)
        name = "netscope_alerts.csv"
        mimetype = "text/csv"
    elif kind == "flows":
        content = pd.DataFrame(result.get("flows", [])).to_csv(index=False)
        name = "netscope_flows.csv"
        mimetype = "text/csv"
    elif kind == "hosts":
        content = pd.DataFrame(result.get("hosts", [])).to_csv(index=False)
        name = "netscope_hosts.csv"
        mimetype = "text/csv"
    elif kind == "report":
        content = json.dumps(build_report(result), indent=2)
        name = "netscope_investigation_report.json"
        mimetype = "application/json"
    elif kind == "csv-analysis":
        q = result.get("quality", {})
        rows = [
            {"section":"Dataset", "metric":"source", "value":result.get("provenance", {}).get("filename", "current dataset")},
            {"section":"Dataset", "metric":"records", "value":result.get("summary", {}).get("records", 0)},
            {"section":"Dataset", "metric":"ipv4_records", "value":result.get("summary", {}).get("ipv4_records", 0)},
            {"section":"Dataset", "metric":"total_bytes", "value":result.get("summary", {}).get("total_bytes", 0)},
            {"section":"Dataset", "metric":"anomaly_findings", "value":result.get("summary", {}).get("alerts", 0)},
            {"section":"Quality", "metric":"invalid_or_non_ipv4_rows", "value":q.get("invalid_or_non_ipv4_rows", 0)},
            {"section":"Quality", "metric":"duplicate_rows", "value":q.get("duplicate_rows", 0)},
            {"section":"Quality", "metric":"missing_timestamps", "value":q.get("missing_timestamps", 0)},
            {"section":"Quality", "metric":"missing_source_ports", "value":q.get("missing_source_ports", 0)},
            {"section":"Quality", "metric":"missing_destination_ports", "value":q.get("missing_destination_ports", 0)},
        ]
        for item in result.get("protocol_distribution", []):
            rows.append({"section":"Protocol", "metric":item.get("protocol", "Unknown"), "value":item.get("count", 0)})
        for item in result.get("alerts", []):
            rows.append({"section":"Finding", "metric":item.get("finding_id", ""), "value":f"{item.get('severity', '')}: {item.get('reason', '')}"})
        content = pd.DataFrame(rows).to_csv(index=False)
        name = "netscope_csv_analysis_summary.csv"
        mimetype = "text/csv"
    else:
        return jsonify(error="Unknown export type."), 404
    return send_file(io.BytesIO(content.encode("utf-8")), mimetype=mimetype, as_attachment=True, download_name=name)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
