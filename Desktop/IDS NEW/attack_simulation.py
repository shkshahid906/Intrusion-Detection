import socket
import time

# Simple port scan attack simulation

def port_scan(target_ip, ports, delay=0.1):
    print(f"Starting port scan on {target_ip}...")
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((target_ip, port))
            if result == 0:
                print(f"Port {port} is open")
            s.close()
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
        time.sleep(delay)
    print("Port scan completed.")

if __name__ == "__main__":
    # Replace with the IP of the machine running the IDS
    target = "127.0.0.1"
    # Common ports to scan
    ports_to_scan = list(range(20, 1025))
    port_scan(target, ports_to_scan)
