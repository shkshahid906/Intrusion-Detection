from scapy.all import send, IP, TCP
import time

TARGET_IP = "192.168.15.23"  # Replace with your test machine's IP
PORT = 80  # Common web traffic port
PACKET_COUNT = 60  # Number of packets to send (above IDS threshold)
DELAY = 0.1  # Time delay between packets

print(f"🚀 Sending {PACKET_COUNT} packets to {TARGET_IP} for IDS testing...")

for _ in range(PACKET_COUNT):
    pkt = IP(dst=TARGET_IP) / TCP(dport=PORT, flags="S")  # Simulates connection attempts
    send(pkt, verbose=False)
    time.sleep(DELAY)

print("✅ Test completed! Check your IDS logs for detection results.")