import os
from scapy.all import sniff, IP
from collections import defaultdict
import time
import smtplib
from email.mime.text import MIMEText
import json
import logging
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
import numpy as np
from threading import Thread
import requests
import socket

# Tracking packet count and timestamps
ip_counter = defaultdict(int)
ip_last_seen = defaultdict(float)

# Load configuration from JSON file
def load_config():  
    """Loads configuration from a JSON file"""
    with open("config.json", "r") as file:
        return json.load(file)

config = load_config()
REQUEST_LIMIT = config["request_limit"]
TIME_WINDOW = config["time_window"]
ALERT_COOLDOWN = config["alert_cooldown"]
LOG_FILE = config["log_file"]
WHITELIST = set(config["whitelist"])

# Thresholds for detection
ALERTED_IPS = set()  # Track IPs that have already triggered alerts
last_alert_time = defaultdict(float)

# Define the path to the whitelist file
WHITELIST_FILE = "whitelist.json"

def load_whitelist():
    """Loads the whitelist from a JSON file"""
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "r") as file:
            return set(json.load(file))
    return set()

def save_whitelist(whitelist):
    """Saves the whitelist to a JSON file"""
    with open(WHITELIST_FILE, "w") as file:
        json.dump(list(whitelist), file)

# Load whitelist at startup
WHITELIST = load_whitelist()

def block_ip(ip):
    """Blocks an IP using Windows Firewall, except whitelisted ones"""
    if ip not in WHITELIST:
        os.system(f"netsh advfirewall firewall add rule name='Block {ip}' dir=in action=block remoteip={ip}")
        print(f"⛔ [BLOCKED] IP {ip} has been blocked!")
    else:
        print(f"✅ [WHITELISTED] IP {ip} was ignored.")

# Configure logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def log_intrusion(ip, count):
    """Logs intrusion alerts to a file and console"""
    message = f"ALERT: {ip}, Packets: {count}"
    logging.info(message)
    print(message)

def send_email_alert(ip, count):
    """Sends an email alert for detected intrusions"""
    sender = "shkshaadu@gmail.com"
    recipient = "shkofficial906@gmail.com"
    subject = "Intrusion Alert"
    body = f"Suspicious activity detected from IP {ip}. Packets: {count}"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient

    try:
        with smtplib.SMTP("smtp.example.com", 587) as server:
            server.starttls()
            server.login(sender, "Shkshaadu@1234")
            server.sendmail(sender, recipient, msg.as_string())
        print(f"📧 Email alert sent to {recipient}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

def detect_intrusion(pkt):
    """Detects suspicious IP traffic and applies mitigation"""
    if IP in pkt:
        src_ip = pkt[IP].src
        current_time = time.time()

        # Reset count if time window passed
        if current_time - ip_last_seen[src_ip] > TIME_WINDOW:
            ip_counter[src_ip] = 0

        ip_counter[src_ip] += 1
        ip_last_seen[src_ip] = current_time

        # Detect suspicious activity and log/block it
        if ip_counter[src_ip] > REQUEST_LIMIT and src_ip not in ALERTED_IPS:
            if current_time - last_alert_time[src_ip] > ALERT_COOLDOWN:
                print(f"[ALERT] Possible intrusion detected from {src_ip}! Packets: {ip_counter[src_ip]}")
                log_intrusion(src_ip, ip_counter[src_ip])
                block_ip(src_ip)
                ALERTED_IPS.add(src_ip)
                last_alert_time[src_ip] = current_time

                # Fetch and save IP information
                ip_info = fetch_ip_info(src_ip)
                if ip_info:
                    save_ip_info(src_ip, ip_info)

def detect_anomalies():
    """Detects anomalies using Isolation Forest"""
    data = np.array(list(ip_counter.values())).reshape(-1, 1)
    model = IsolationForest(contamination=0.1)
    model.fit(data)
    anomalies = model.predict(data)

    for ip, anomaly in zip(ip_counter.keys(), anomalies):
        if anomaly == -1:  # Anomaly detected
            print(f"[ANOMALY] Suspicious activity detected from {ip}")

def visualize_traffic():
    """Visualizes traffic patterns"""
    ips = list(ip_counter.keys())
    counts = list(ip_counter.values())

    plt.bar(ips, counts, color="blue")
    plt.xlabel("IP Addresses")
    plt.ylabel("Packet Count")
    plt.title("Traffic Patterns")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()

def start_sniffing():
    """Starts packet sniffing"""
    sniff(filter="ip", prn=detect_intrusion, store=0)

# Run sniffing in a separate thread
sniff_thread = Thread(target=start_sniffing)
sniff_thread.start()

# Start sniffing (requires admin privileges)
print("🔍 Starting Advanced IDS... Press Ctrl+C to stop.")
sniff(filter="ip", prn=detect_intrusion, store=0)

import json

IP_INFO_FILE = "ip_info.json"

def fetch_ip_info(ip):
    """Fetches information about an IP address using the ipinfo.io API"""
    try:
        # Replace 'your_token' with your actual API token
        token = os.getenv("IPINFO_TOKEN")
        response = requests.get(f"https://ipinfo.io/{ip}/json?token={token}")
        if response.status_code == 200:
            return response.json()
        else:
            print(f"❌ Failed to fetch info for IP {ip}: {response.status_code}")
            return None
    except Exception as e:
        print(f"❌ Error fetching IP info: {e}")
        return None

def save_ip_info(ip, info):
    """Saves IP information to a JSON file"""
    if not os.path.exists(IP_INFO_FILE):
        data = {}
    else:
        with open(IP_INFO_FILE, "r") as file:
            data = json.load(file)

    data[ip] = info

    with open(IP_INFO_FILE, "w") as file:
        json.dump(data, file, indent=4)
    print(f"📁 IP information for {ip} saved to {IP_INFO_FILE}")

def get_hostname(ip):
    """Gets the hostname of an IP address"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"