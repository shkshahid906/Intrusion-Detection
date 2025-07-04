# ids_engine.py
from scapy.all import sniff, IP
from collections import deque, Counter
import threading
import time
import json
import os
import requests

from kasper import kasper_scan  # Your custom detection logic

LOG_FILE = "intrusion.log"
BLOCKED_IP_FILE = "blocked_ips.json"

# Data stores
ip_counter = Counter()
blocked_ips = set()
recent_ip_flows = deque(maxlen=100)
ip_location_cache = {}

# Load previously blocked IPs
def load_blocked_ips():
    global blocked_ips
    try:
        with open(BLOCKED_IP_FILE, "r") as f:
            blocked_ips = set(json.load(f))
    except:
        blocked_ips = set()

def save_blocked_ips():
    with open(BLOCKED_IP_FILE, "w") as f:
        json.dump(list(blocked_ips), f)

# Geolocation
def geolocate_ip(ip):
    if ip in ip_location_cache:
        return ip_location_cache[ip]
    try:
        # Skip private IPs
        if ip.startswith("192.") or ip.startswith("10.") or ip.startswith("127.") or ip.startswith("172."):
            return [0, 0]

        url = f"http://ip-api.com/json/{ip}"
        res = requests.get(url, timeout=3)
        data = res.json()
        if data['status'] == 'success':
            latlng = [data['lat'], data['lon']]
            ip_location_cache[ip] = latlng
            return latlng
        else:
            print(f"❌ Failed geo lookup for {ip}: {data}")
    except Exception as e:
        print(f"[Geo] Error for {ip}: {e}")
    return [0, 0]


# Packet processing
def process_packet(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        ip_counter[src_ip] += 1
        recent_ip_flows.append((src_ip, dst_ip))

        alert = kasper_scan(pkt)
        if alert and src_ip not in blocked_ips:
            log = f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Alert: {alert['reason']} from {src_ip}"
            print(log)
            with open(LOG_FILE, "a") as f:
                f.write(log + "\n")
            blocked_ips.add(src_ip)
            save_blocked_ips()
            os.system(f'netsh advfirewall firewall add rule name="Block {src_ip}" dir=in interface=any action=block remoteip={src_ip}')

# Background IDS thread
def run_ids_in_thread():
    print("✅ IDS Thread started...")

    # ✅ Simulate Google to Cloudflare
    recent_ip_flows.append(("8.8.8.8", "1.1.1.1"))
    ip_counter.update({"8.8.8.8": 12, "1.1.1.1": 6})

    t = threading.Thread(target=lambda: sniff(prn=process_packet, store=False))
    t.daemon = True
    t.start()



# API functions
def get_ip_data():
    return dict(ip_counter)

def get_blocked_ips():
    return list(blocked_ips)

def get_ip_locations():
    return {
        ip: geolocate_ip(ip)
        for ip in list(ip_counter.keys())[:50]
    }

def get_ip_flows():
    result = []
    for src, dst in list(recent_ip_flows)[-20:]:
        src_coords = geolocate_ip(src)
        dst_coords = geolocate_ip(dst)

        if src_coords == [0, 0] and dst_coords == [0, 0]:
            print(f"⚠️ Skipping private or unresolved IP flow: {src} → {dst}")
            continue

        result.append({
            "src_ip": src,
            "dst_ip": dst,
            "src_coords": src_coords,
            "dst_coords": dst_coords
        })

    print(f"[🌍] Returning {len(result)} flows: {result}")
    return result


