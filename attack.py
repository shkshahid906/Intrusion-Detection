# attack_simulator.py
from scapy.all import IP, TCP, send
import time

def syn_flood(target_ip="127.0.0.1", target_ports=range(20, 30), delay=0.1):
    print(f"[⚠️] Simulating SYN scan from {target_ip} to ports {list(target_ports)}")
    for port in target_ports:
        pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(delay)
    print("[✅] SYN scan complete.")

if __name__ == "__main__":
    syn_flood("127.0.0.1", range(20, 1024), delay=0.01)
