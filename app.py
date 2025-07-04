from flask import Flask, render_template, jsonify, request, redirect, send_file
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io
from random import uniform, randint, choice
import os

from ids_engine import (
    run_ids_in_thread,
    get_ip_data,
    get_blocked_ips,
    get_ip_locations,
    get_ip_flows,
    ip_counter,
    blocked_ips,
    save_blocked_ips
)

app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# Dummy public targets
public_targets = [
    "8.8.8.8",    # Google
    "1.1.1.1",    # Cloudflare
    "13.107.21.200",  # Microsoft
    "185.199.108.153", # GitHub
    "104.244.42.1",  # Twitter
    "172.217.160.142" # Google
]

# 🔁 Store live attack flows
ip_flows = []

# Start IDS on server start
run_ids_in_thread()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/graph")
def traffic_graph():
    if not ip_counter:
        ip_counter.update({"8.8.8.8": 5, "1.1.1.1": 3})

    labels = list(ip_counter.keys())[-10:]
    data = list(ip_counter.values())[-10:]

    plt.clf()
    fig = plt.figure(figsize=(8, 4))
    plt.bar(labels, data, color='skyblue')
    plt.xticks(rotation=45, ha='right')
    plt.title("Live IP Traffic")
    plt.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format='png')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

@app.route("/live_ips")
def live_ips():
    try:
        return jsonify(get_ip_data())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/blocked_ips")
def blocked_ips_route():
    try:
        return jsonify(get_blocked_ips())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/locations")
def locations():
    try:
        return jsonify(get_ip_locations())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/ip_flows")
def ip_flows_route():
    try:
        return jsonify(get_ip_flows())  # Will now return live flows ✅
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/unblock_ip", methods=["POST"])
def unblock_ip():
    ip = request.form.get("ip")
    if ip and ip in blocked_ips:
        blocked_ips.remove(ip)
        save_blocked_ips()
        os.system(f'netsh advfirewall firewall delete rule name="Block {ip}"')
    return redirect("/")

@app.route("/clear_logs")
def clear_logs():
    open('intrusion.log', 'w').close()
    return redirect('/')

@app.route("/export_logs")
def export_logs():
    if os.path.exists("intrusion.log"):
        return send_file("intrusion.log", as_attachment=True)
    return "Log file not found", 404

@app.route("/simulate")
def simulate():
    ip_counter.update({"123.123.123.123": 7, "45.45.45.45": 3})
    with open("intrusion.log", "a") as f:
        f.write(f"Simulated attack from 123.123.123.123\n")
    return redirect("/")

# --- Utility ---
def is_private_ip(ip):
    return ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127.") or ip.startswith("172.")

def random_coords():
    return [uniform(-60, 80), uniform(-180, 180)]

def generate_random_public_ip():
    return ".".join(str(randint(1, 254)) for _ in range(4))

# --- Simulate Multiple Attacks ---
@app.route('/simulate_bulk')
def simulate_bulk_attacks():
    global ip_flows
    ip_flows = []

    for _ in range(20):
        src_ip = generate_random_public_ip()
        dst_ip = choice(public_targets)
        if is_private_ip(src_ip) or is_private_ip(dst_ip):
            continue
        ip_flows.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_coords": random_coords(),
            "dst_coords": random_coords()
        })

    print(f"[🚀] Simulated {len(ip_flows)} attack flows.")
    return redirect('/')

# Expose ip_flows for access in ids_engine
def get_flows_list():
    return ip_flows

if __name__ == "__main__":
    app.run(debug=True)
