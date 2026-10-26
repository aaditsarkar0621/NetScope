import pandas as pd
import numpy as np
import ipaddress, math, json
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

ALIASES = {
    "timestamp":["timestamp","time","datetime","date","ts","start_time","stime"],
    "source_ip":["source_ip","src_ip","src","source","srcip","ip_src","source address","src addr"],
    "destination_ip":["destination_ip","dst_ip","dst","destination","dstip","ip_dst","destination address","dst addr"],
    "source_port":["source_port","sport","src_port","sourceport"],
    "destination_port":["destination_port","dport","dst_port","destinationport"],
    "transport_protocol":["transport_protocol","protocol","proto","ip_protocol"],
    "ip_length":["ip_length","length","packet_length","tot_len","total_length","bytes","flow_bytes"],
    "packet_count":["packet_count","packets","total_packets","flow_packets"],
    "duration":["duration","flow_duration","dur"],
    "ttl":["ttl","ip_ttl"],
    "src_mac":["src_mac","source_mac","eth_src","srcmac"],
    "dst_mac":["dst_mac","destination_mac","eth_dst","dstmac"],
    "tcp_flags":["tcp_flags","flags"],
    "ipv4_checksum_status":["ipv4_checksum_status","checksum_status","ip_checksum_status"]
}

def _colmap(df):
    lower = {str(c).strip().lower():c for c in df.columns}
    result = {}
    for canonical, candidates in ALIASES.items():
        for c in candidates:
            if c in lower:
                result[canonical] = lower[c]
                break
    return result

def _is_ipv4(v):
    try:
        return ipaddress.ip_address(str(v).strip()).version == 4
    except Exception:
        return False

def _ip_class(v):
    try:
        ip = ipaddress.ip_address(str(v).strip())
        if ip.is_loopback: return "Loopback"
        if ip.is_private: return "Private"
        if ip.is_multicast: return "Multicast"
        if ip.is_link_local: return "Link-local"
        if ip.is_reserved or ip.is_unspecified: return "Reserved/special"
        return "Public"
    except Exception:
        return "Invalid/missing"

def make_demo_data():
    rng = np.random.default_rng(42)
    rows=[]
    start=pd.Timestamp.now().floor("s")-pd.Timedelta(minutes=10)
    hosts=["192.168.1.10","192.168.1.20","192.168.1.30","10.0.0.5","8.8.8.8","1.1.1.1","203.0.113.8"]
    for i in range(220):
        src=hosts[int(rng.integers(0,5))]
        dst=hosts[int(rng.integers(2,len(hosts)))]
        if src==dst: dst="8.8.8.8"
        proto=str(rng.choice(["TCP","TCP","UDP","UDP","ICMP"]))
        dport=int(rng.choice([53,80,443,123,22,8080,3389,random_port(rng)]))
        length=int(max(60,rng.normal(620,190)))
        ttl=int(rng.choice([64,128,255]))
        if i in range(6):
            src="192.168.1.10"; dport=int(1000+i); length=int(rng.integers(1000,1450)); proto="TCP"
        rows.append({"timestamp":(start+pd.Timedelta(seconds=i*2)).isoformat(),"source_ip":src,"destination_ip":dst,
                     "transport_protocol":proto,"source_port":int(rng.integers(20000,65000)),"destination_port":dport,
                     "ip_length":length,"packet_count":1,"ttl":ttl,"src_mac":f"02:00:00:00:{int(i%255):02x}:10",
                     "dst_mac":f"02:00:00:00:{int((i+1)%255):02x}:20"})
    return pd.DataFrame(rows)

def random_port(rng):
    return int(rng.integers(1024,65000))

def normalize_dataframe(df):
    original_count=len(df)
    mapping=_colmap(df)
    out=pd.DataFrame(index=df.index)
    for field, source in mapping.items():
        out[field]=df[source]
    for field in ["timestamp","source_ip","destination_ip","transport_protocol","ip_length"]:
        if field not in out:
            out[field]=pd.NaT if field=="timestamp" else (np.nan if field=="ip_length" else "")
    if "timestamp" in out:
        out["timestamp"]=pd.to_datetime(out["timestamp"],errors="coerce",utc=True)
    for f in ["source_port","destination_port","ip_length","packet_count","duration","ttl"]:
        if f not in out: out[f]=np.nan
        out[f]=pd.to_numeric(out[f],errors="coerce")
    for f in ["src_mac","dst_mac","tcp_flags","ipv4_checksum_status"]:
        if f not in out: out[f]=""
        out[f]=out[f].fillna("").astype(str)
    out["transport_protocol"]=out["transport_protocol"].fillna("Unknown").astype(str).str.upper().str.strip()
    out["source_ip"]=out["source_ip"].fillna("").astype(str).str.strip()
    out["destination_ip"]=out["destination_ip"].fillna("").astype(str).str.strip()
    out["source_ipv4_valid"]=out["source_ip"].map(_is_ipv4)
    out["destination_ipv4_valid"]=out["destination_ip"].map(_is_ipv4)
    out["ipv4_valid"]=out["source_ipv4_valid"] & out["destination_ipv4_valid"]
    out["source_ip_class"]=out["source_ip"].map(_ip_class)
    out["destination_ip_class"]=out["destination_ip"].map(_ip_class)
    out["row_id"]=np.arange(1,len(out)+1)
    out["ip_length"]=out["ip_length"].fillna(0).clip(lower=0)
    out["packet_count"]=out["packet_count"].fillna(1).clip(lower=0)
    out["duration"]=out["duration"].fillna(0).clip(lower=0)
    out["source_port"]=out["source_port"].where(out["source_port"].between(0,65535))
    out["destination_port"]=out["destination_port"].where(out["destination_port"].between(0,65535))
    quality={"input_rows":original_count,"accepted_ipv4_rows":int(out["ipv4_valid"].sum()),
             "invalid_or_non_ipv4_rows":int((~out["ipv4_valid"]).sum()),
             "missing_timestamps":int(out["timestamp"].isna().sum()),
             "missing_source_ports":int(out["source_port"].isna().sum()),
             "missing_destination_ports":int(out["destination_port"].isna().sum()),
             "duplicate_rows":int(df.duplicated().sum()),"columns_detected":mapping,
             "unmapped_columns":[str(c) for c in df.columns if c not in mapping.values()]}
    return out,quality

def _robust_z(x, values):
    vals=np.asarray(values,dtype=float)
    vals=vals[np.isfinite(vals)]
    if len(vals)<8: return 0.0, "Insufficient baseline"
    med=float(np.median(vals))
    mad=float(np.median(np.abs(vals-med)))
    if mad < 1e-9:
        scale=float(np.std(vals))
        if scale < 1e-9:
            return (6.0 if abs(float(x)-med)>1e-9 else 0.0), f"Baseline median {med:.2f}; MAD≈0"
        z=(float(x)-med)/scale
    else:
        z=0.6745*(float(x)-med)/mad
    return float(z), f"Observed {float(x):.2f}; baseline median {med:.2f}; MAD {mad:.2f}"

DEFAULT_THRESHOLDS = {"robust_z": 3.0, "unique_ports": 8, "source_packets": 100}

def analyze_dataframe(df, return_normalized=False, thresholds=None):
    thresholds = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    raw_rows=len(df)
    n,quality=normalize_dataframe(df)
    valid=n[n["ipv4_valid"]].copy()
    if valid.empty:
        valid=n.copy()
    # Build feature-rich flows using the directional 5-tuple; absent ports remain nullable.
    keycols=["source_ip","destination_ip","source_port","destination_port","transport_protocol"]
    valid["source_port_key"]=valid["source_port"].fillna(-1).astype(int)
    valid["destination_port_key"]=valid["destination_port"].fillna(-1).astype(int)
    groups=valid.groupby(["source_ip","destination_ip","source_port_key","destination_port_key","transport_protocol"],dropna=False)
    flows=[]
    for idx, (key,g) in enumerate(groups,1):
        times=g["timestamp"].dropna()
        duration=max(0.0,(times.max()-times.min()).total_seconds()) if len(times)>1 else float(g["duration"].sum())
        flows.append({"flow_id":f"F{idx:04d}","source_ip":key[0],"destination_ip":key[1],
                      "source_port":None if key[2]<0 else int(key[2]),"destination_port":None if key[3]<0 else int(key[3]),
                      "protocol":key[4],"packets":int(g["packet_count"].sum()),"bytes":int(g["ip_length"].sum()),
                      "duration_seconds":round(duration,3),"first_seen":times.min().isoformat() if len(times) else None,
                      "last_seen":times.max().isoformat() if len(times) else None,"record_ids":g["row_id"].astype(int).tolist()})
    flowdf=pd.DataFrame(flows)
    if flowdf.empty:
        flowdf=pd.DataFrame(columns=["flow_id","source_ip","destination_ip","source_port","destination_port","protocol","packets","bytes","duration_seconds","first_seen","last_seen","record_ids"])
    # Statistical baseline by source host: packet/byte volume and destination port diversity.
    host_windows=[]
    for host,g in valid.groupby("source_ip"):
        host_windows.append({"host":host,"packets":int(g["packet_count"].sum()),"bytes":int(g["ip_length"].sum()),
            "unique_peers":int(g["destination_ip"].nunique()),"unique_destination_ports":int(g["destination_port"].nunique()),
            "protocols":", ".join(sorted(g["transport_protocol"].dropna().unique())),
            "classification":_ip_class(host),"records":int(len(g)),
            "mean_packet_bytes":round(float(g["ip_length"].mean()),2) if len(g) else 0,
            "ttl_median":float(g["ttl"].median()) if g["ttl"].notna().any() else None,
            "src_mac":next((x for x in g["src_mac"].tolist() if x), ""),
            "last_seen":g["timestamp"].max().isoformat() if g["timestamp"].notna().any() else None})
    hosts=sorted(host_windows,key=lambda x:x["bytes"],reverse=True)
    # Statistical anomaly score over flows with robust scaling. Use feature columns only, never raw IP strings.
    alerts=[]
    features=pd.DataFrame({
        "log_bytes":np.log1p(pd.to_numeric(flowdf["bytes"],errors="coerce").fillna(0)),
        "log_packets":np.log1p(pd.to_numeric(flowdf["packets"],errors="coerce").fillna(0)),
        "log_duration":np.log1p(pd.to_numeric(flowdf["duration_seconds"],errors="coerce").fillna(0)),
        "destination_port":pd.to_numeric(flowdf["destination_port"],errors="coerce").fillna(-1),
        "source_port":pd.to_numeric(flowdf["source_port"],errors="coerce").fillna(-1),
        "protocol_code":flowdf["protocol"].astype(str).map({"TCP":6,"UDP":17,"ICMP":1,"ICMPV6":58}).fillna(0),
    }) if len(flowdf) else pd.DataFrame()
    iso_scores=np.zeros(len(flowdf))
    iso_flags=np.zeros(len(flowdf),dtype=bool)
    if len(flowdf)>=20:
        scaler=StandardScaler()
        X=scaler.fit_transform(features.replace([np.inf,-np.inf],0).fillna(0))
        model=IsolationForest(n_estimators=150, contamination="auto", random_state=42)
        model.fit(X)
        raw=-model.score_samples(X)
        cutoff=float(np.quantile(raw,0.95))
        iso_scores=np.clip((raw/(max(float(np.max(raw)),1e-6))*100),0,100)
        iso_flags=raw>=cutoff
    flow_stats={}
    if len(flowdf):
        for _,r in flowdf.iterrows():
            flow_stats[r["flow_id"]]=r
    # Source host port diversity and byte/packet baseline; robust score across hosts' flow-level values.
    port_rule_hosts=set()
    for i, flow in flowdf.iterrows():
        evidence=[]
        zbytes, expl_bytes=_robust_z(flow["bytes"],flowdf["bytes"].tolist())
        zpackets, expl_packets=_robust_z(flow["packets"],flowdf["packets"].tolist())
        score=max(abs(zbytes),abs(zpackets))
        detectors=[]
        if abs(zbytes)>=float(thresholds["robust_z"]):
            detectors.append("Robust MAD score")
            evidence.append({"feature":"flow_bytes","observed":int(flow["bytes"]),"explanation":expl_bytes})
        if abs(zpackets)>=float(thresholds["robust_z"]):
            detectors.append("Robust MAD score")
            evidence.append({"feature":"flow_packets","observed":int(flow["packets"]),"explanation":expl_packets})
        # Host-specific destination diversity: use host aggregate compared to peers (descriptive rule).
        h=next((x for x in hosts if x["host"]==flow["source_ip"]),None)
        if h and h["unique_destination_ports"]>=int(thresholds["unique_ports"]) and flow["source_ip"] not in port_rule_hosts:
            port_rule_hosts.add(flow["source_ip"])
            detectors.append("Port-diversity rule")
            evidence.append({"feature":"unique_destination_ports","observed":h["unique_destination_ports"],
                             "explanation":f"Source host contacted {h['unique_destination_ports']} distinct destination ports."})
            score=max(score,3.5)
        if h and h["packets"] >= int(thresholds["source_packets"]):
            detectors.append("High source packet volume")
            evidence.append({"feature":"source_packets","observed":h["packets"],
                             "explanation":f"Source host has {h['packets']} packets in the analysed dataset; configured threshold is {int(thresholds['source_packets'])}."})
            score=max(score,4.0)
        if len(flowdf)>=20 and bool(iso_flags[i]):
            detectors.append("Isolation Forest")
            evidence.append({"feature":"isolation_forest_score","observed":round(float(iso_scores[i]),2),
                             "explanation":"This flow lies in the most unusual 5% of the current flow feature distribution."})
            score=max(score,3.5)
        if detectors:
            severity="High" if score>=6 or len(set(detectors))>=2 else "Medium"
            alerts.append({"finding_id":f"A{len(alerts)+1:04d}","timestamp":flow["first_seen"],"source_host":flow["source_ip"],
                           "destination_host":flow["destination_ip"],"protocol":flow["protocol"],"destination_port":flow["destination_port"],
                           "flow_id":flow["flow_id"],"severity":severity,"score":round(float(score),2),
                           "detectors":", ".join(dict.fromkeys(detectors)),"reason":"; ".join(e["explanation"] for e in evidence),
                           "evidence":evidence,"record_ids":flow["record_ids"],"status":"New",
                           "interpretation":"Unusual behaviour to investigate; not proof of malicious activity."})
    # checksum data is only reported when supplied; CSV metadata cannot independently verify raw IP checksum.
    checksum_col="ipv4_checksum_status"
    checks={"valid":0,"invalid":0,"inconclusive":int(len(valid))}
    if checksum_col in n and n[checksum_col].astype(str).str.strip().ne("").any():
        statuses=n[checksum_col].astype(str).str.lower()
        checks={"valid":int(statuses.str.contains("valid|ok|pass",regex=True).sum()),
                "invalid":int(statuses.str.contains("invalid|fail|bad",regex=True).sum()),
                "inconclusive":int(statuses.str.contains("inconclusive|not applicable|unknown|^$",regex=True).sum())}
    protocol_dist=valid["transport_protocol"].value_counts().to_dict()
    edge_map={}
    for _,f in flowdf.iterrows():
        key=(f["source_ip"],f["destination_ip"])
        if key not in edge_map: edge_map[key]={"source":key[0],"target":key[1],"packets":0,"bytes":0,"flows":0}
        edge_map[key]["packets"]+=int(f["packets"]); edge_map[key]["bytes"]+=int(f["bytes"]); edge_map[key]["flows"]+=1
    nodes=[{"id":h["host"],"label":h["host"],"bytes":h["bytes"],"packets":h["packets"],"classification":h["classification"]} for h in hosts]
    time_series=[]
    timed=valid.dropna(subset=["timestamp"]).copy()
    if len(timed):
        timed["minute"]=timed["timestamp"].dt.floor("min").astype(str)
        for k,g in timed.groupby("minute"):
            time_series.append({"time":k,"packets":int(g["packet_count"].sum()),"bytes":int(g["ip_length"].sum())})
    result={"summary":{"records":int(raw_rows),"ipv4_records":int(n["ipv4_valid"].sum()),"invalid_records":int((~n["ipv4_valid"]).sum()),
                       "hosts":len(hosts),"flows":len(flowdf),"alerts":len(alerts),"total_bytes":int(valid["ip_length"].sum()),
                       "protocols":len(protocol_dist),"mean_packet_bytes":round(float(valid["ip_length"].mean()),2) if len(valid) else 0},
             "quality":quality,"hosts":hosts,"flows":flows,"alerts":alerts,"protocol_distribution":[{"protocol":str(k),"count":int(v)} for k,v in protocol_dist.items()],
             "top_talkers":hosts[:10],"top_ports":[{"port":int(k),"count":int(v)} for k,v in valid["destination_port"].dropna().astype(int).value_counts().head(12).items()],
             "topology":{"nodes":nodes,"edges":list(edge_map.values())},"time_series":time_series,
             "checksum_summary":checks,
             "ipv4_summary":{"private_sources":int(n["source_ip_class"].eq("Private").sum()),"public_sources":int(n["source_ip_class"].eq("Public").sum()),
                             "loopback_sources":int(n["source_ip_class"].eq("Loopback").sum()),"invalid_ipv4_rows":int((~n["ipv4_valid"]).sum()),
                             "ttl_available":int(n["ttl"].notna().sum()),"fragmentation_available":False},
             "detection":{"algorithms":["Median Absolute Deviation / robust Z-score","Isolation Forest (when ≥20 flows)","Host port-diversity rule"],
                          "baseline":"Current dataset distribution; host-specific history is limited unless historical windows are supplied.",
                          "note":"Scores rank unusual observations, not confirmed attacks. Statistical cutoffs are heuristic and should be calibrated on labelled validation data."},
             "provenance":{"source":"CSV or demo","filename":"in-memory dataset","rows":int(raw_rows),"analyzed_at":pd.Timestamp.now(tz="UTC").isoformat(),
                           "software_version":"NetScope 2.0","sha256":None}}
    if return_normalized: return result,n
    return result

def build_report(result):
    return {"report_title":"NetScope Investigation Report","generated_at":pd.Timestamp.now(tz="UTC").isoformat(),
            "summary":result.get("summary"),"provenance":result.get("provenance"),"quality":result.get("quality"),
            "ipv4_summary":result.get("ipv4_summary"),"checksum_summary":result.get("checksum_summary"),
            "detection":result.get("detection"),"hosts":result.get("hosts"),"flows":result.get("flows"),
            "alerts":result.get("alerts"),"limitations":["Anomaly is not proof of malicious activity.",
            "Checksum verification requires raw IPv4 header bytes; CSV status is reported only when supplied.",
            "MAC addresses and IPv4 details depend on source schema and capture visibility."]}
