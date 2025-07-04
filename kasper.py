# kasper.py
from scapy.all import TCP

# Track SYN attempts
syn_tracker = {}

def kasper_scan(pkt):
    if TCP in pkt and pkt[TCP].flags == 'S':  # SYN flag only
        ip = pkt[0][1].src
        syn_tracker[ip] = syn_tracker.get(ip, 0) + 1

        if syn_tracker[ip] > 20:  # Threshold
            return {"reason": "Port Scan Detected"}

    return None
