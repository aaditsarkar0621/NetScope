import threading
import time
from datetime import datetime, timezone
from collections import deque

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, ARP, IPv6, get_if_list
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

_LOCK = threading.RLock()
_RECORDS = deque(maxlen=10000)
_THREAD = None
_STOP = threading.Event()
_STATUS = {"running": False, "paused": False, "interface": None, "error": None, "started_at": None, "packets_seen": 0}

def capture_available():
    return SCAPY_AVAILABLE

def list_interfaces():
    if not SCAPY_AVAILABLE:
        return []
    try:
        return get_if_list()
    except Exception:
        return []

def _decode(pkt):
    row = {"timestamp": datetime.fromtimestamp(float(pkt.time), timezone.utc).isoformat(), "source_ip": "", "destination_ip": "", "transport_protocol": "Other",
           "ip_length": len(pkt), "source_port": None, "destination_port": None, "ttl": None,
           "src_mac": pkt[Ether].src if Ether in pkt else "", "dst_mac": pkt[Ether].dst if Ether in pkt else "",
           "ipv4_checksum_status": ""}
    if IP in pkt:
        ip = pkt[IP]
        row.update(source_ip=ip.src, destination_ip=ip.dst, transport_protocol="IPv4", ip_length=int(ip.len), ttl=int(ip.ttl))
        try:
            from scapy.layers.inet import checksum
            header = bytes(ip)[:int(ip.ihl) * 4]
            row["ipv4_checksum_status"] = "valid" if checksum(header) == 0 else "invalid"
        except Exception:
            row["ipv4_checksum_status"] = "inconclusive"
        if TCP in pkt:
            row.update(transport_protocol="TCP", source_port=int(pkt[TCP].sport), destination_port=int(pkt[TCP].dport), tcp_flags=str(pkt[TCP].flags))
        elif UDP in pkt:
            row.update(transport_protocol="UDP", source_port=int(pkt[UDP].sport), destination_port=int(pkt[UDP].dport))
        elif ICMP in pkt:
            row["transport_protocol"] = "ICMP"
    elif ARP in pkt:
        row.update(transport_protocol="ARP", source_ip=pkt[ARP].psrc or "", destination_ip=pkt[ARP].pdst or "")
    elif IPv6 in pkt:
        row.update(transport_protocol="IPv6", source_ip=pkt[IPv6].src, destination_ip=pkt[IPv6].dst, ttl=int(pkt[IPv6].hlim))
    return row

def _worker(interface):
    try:
        def collect(pkt):
            if _STOP.is_set():
                return
            with _LOCK:
                if _STATUS.get("paused"):
                    return
            row = _decode(pkt)
            with _LOCK:
                _RECORDS.append(row)
                _STATUS["packets_seen"] += 1
        while not _STOP.is_set():
            sniff(iface=interface or None, prn=collect, store=False, timeout=1)
    except Exception as exc:
        with _LOCK:
            _STATUS["error"] = str(exc)
    finally:
        with _LOCK:
            _STATUS["running"] = False

def start_capture(interface=None):
    global _THREAD
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Live capture requires Scapy and Npcap on Windows. Install Npcap, then run PowerShell as Administrator.")
    with _LOCK:
        if _STATUS["running"]:
            return dict(_STATUS)
        _RECORDS.clear()
        _STOP.clear()
        _STATUS.update(running=True, paused=False, interface=interface, error=None, started_at=time.time(), packets_seen=0)
        _THREAD = threading.Thread(target=_worker, args=(interface,), daemon=True, name="netscope-packet-capture")
        _THREAD.start()
        return dict(_STATUS)

def pause_capture(paused=True):
    with _LOCK:
        if not _STATUS["running"]:
            raise RuntimeError("Capture is not running.")
        _STATUS["paused"] = bool(paused)
        return dict(_STATUS)

def stop_capture():
    _STOP.set()
    with _LOCK:
        thread = _THREAD
    if thread and thread.is_alive():
        thread.join(timeout=3)
    with _LOCK:
        _STATUS["running"] = False
        return dict(_STATUS)

def capture_status():
    with _LOCK:
        return dict(_STATUS)

def captured_records():
    with _LOCK:
        return list(_RECORDS)

def capture_packets(seconds=8, interface=None):
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Live capture requires Scapy and Npcap on Windows. Install Npcap, then run PowerShell as Administrator.")
    records=[]
    sniff(iface=interface or None, prn=lambda pkt: records.append(_decode(pkt)), timeout=seconds, store=False)
    return records
