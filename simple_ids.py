import time
import numpy as np
from scapy.all import sniff, IP, ICMP, Ether, send
from sklearn.ensemble import IsolationForest
import tkinter as tk
from tkinter import ttk
from threading import Thread
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from scipy.interpolate import make_interp_spline
from collections import Counter
import warnings

warnings.filterwarnings("ignore")

# Global variables
feature_history = []
max_rate = 70  # Will be updated dynamically

# Function to extract key features from packets
def collect_features(packets):
    if not packets:
        return [0] * 5, "0.0.0.0", "00:00:00:00:00:00", 0

    count = len(packets)
    sizes = [len(p) for p in packets]
    avg_size = sum(sizes) / count if count > 0 else 0
    size_std = np.std(sizes) if sizes else 0

    src_ips = [p[IP].src for p in packets if IP in p]
    unique_src_ips = len(set(src_ips))
            
    most_frequent_ip = Counter(src_ips).most_common(1)[0][0] if src_ips else "0.0.0.0"
    icmp_count = sum(1 for p in packets if ICMP in p)
    icmp_proportion = icmp_count / count if count > 0 else 0
    src_macs = [p[Ether].src for p in packets if Ether in p]
    unique_macs = len(set(src_macs))
    most_frequent_mac = Counter(src_macs).most_common(1)[0][0] if src_macs else "00:00:00:00:00:00"

    features = [count, avg_size, unique_src_ips, icmp_proportion, unique_macs]
    return features, most_frequent_ip, most_frequent_mac, size_std

# Collect normal traffic data
def collect_training_data(duration=20):
    print(f"Collecting normal traffic data for {duration} seconds...")
    data = []

    for _ in range(duration):
        packets = sniff(timeout=1)
        features, _, _, _ = collect_features(packets)
        data.append(features)
        time.sleep(1)

    filtered_data = [x for x in data if x[0] <= 100]
    if len(filtered_data) < len(data):
        print(f"Filtered out {len(data) - len(filtered_data)} outliers.")
    return np.array(filtered_data)

# Train the Isolation Forest model
def train_model(data):
    global max_rate
    print("Training Isolation Forest model...")
    model = IsolationForest(contamination=0.1, random_state=42)  # Adjusted contamination
    model.fit(data)
    mean_packet_count = np.mean(data[:, 0])
    std_packet_count = np.std(data[:, 0])
    max_rate = mean_packet_count + 2 * std_packet_count  # Dynamic threshold
    print(f"Dynamic max packet rate set to: {max_rate:.2f}")
    return model

# Simulate a ping flood attack
def simulate_ping_flood(target="127.0.0.1", count=5000):
    print("\033[93mSimulating DDoS attack (ping flood)...\033[0m")
    packet = IP(dst=target) / ICMP()
    for _ in range(5):
        for _ in range(count // 5):
            send(packet, verbose=0)
        time.sleep(0.5)
    print("Attack simulation complete.")

# Log alerts to a file
def log_alert(msg):
    with open("ids_log.txt", "a") as f:
        f.write(f"{time.ctime()}: {msg}\n")

# Monitor traffic and update GUI/graph
def monitor_traffic(model, duration=90, label=None, attack_label=None, canvas=None, ax=None, root=None, progress=None):
    global feature_history, max_rate
    print(f"Monitoring traffic for {duration} seconds...")
    min_rate = 3

    for i in range(duration):
        packets = sniff(timeout=1)
        features, top_ip, top_mac, size_std = collect_features(packets)
        feature_history.append(features)
        if len(feature_history) > 30:
            feature_history.pop(0)

        current_features = np.array([features]).reshape(1, -1)
        prediction = model.predict(current_features)
        is_streaming_like = features[3] < 0.1 and features[2] < 5 and size_std < 20  # Streaming check
        is_anomaly = (prediction[0] == -1) and not is_streaming_like and (features[0] >= min_rate)

        if is_anomaly:
            msg = (
                f"ALERT: Anomaly! Packets: {features[0]}, Avg Size: {features[1]:.1f}, "
                f"Unique IPs: {features[2]}, ICMP%: {features[3]:.2f}, Unique MACs: {features[4]}, "
                f"Top IP: {top_ip}, Top MAC: {top_mac}"
            )
            print(f"\033[91m{msg}\033[0m")
            log_alert(msg)
            if label:
                label.config(text=msg, fg="#FF00FF")
                label.after(100, lambda: label.config(fg="#FF00FF" if label["fg"] == "#00FFFF" else "#00FFFF"))
        else:
            msg = (
                f"Normal: Packets: {features[0]}, Avg Size: {features[1]:.1f}, "
                f"Unique IPs: {features[2]}, ICMP%: {features[3]:.2f}, Unique MACs: {features[4]}, "
                f"Top IP: {top_ip}, Top MAC: {top_mac}"
            )
            print(msg)
            if label:
                label.config(text=msg, fg="#00FFFF")

        if i == 45:
            if attack_label:
                attack_label.config(text="Attack: DDoS Active", fg="#FFAA00")
            if root:
                root.configure(bg="#1A0D2E")
            Thread(target=simulate_ping_flood).start()
        elif i == 50 and attack_label:
            attack_label.config(text="Attack: None", fg="#00FF00")
            if root:
                root.configure(bg="#0D0D0D")

        if canvas and ax and i % 2 == 0:
            ax.clear()
            x = np.arange(len(feature_history))
            packet_counts = [f[0] for f in feature_history]
            if len(packet_counts) >= 4:
                x_smooth = np.linspace(x.min(), x.max(), 300)
                spline = make_interp_spline(x, packet_counts, k=3)
                y_smooth = spline(x_smooth)
                ax.plot(x_smooth, y_smooth, label="Packets/sec", color="#00FFFF", linewidth=3, alpha=0.8)
            else:
                ax.plot(x, packet_counts, label="Packets/sec", color="#00FFFF", linewidth=3, alpha=0.8)
            ax.axhline(y=max_rate, color="#FF00FF", linestyle="--", label="Threshold")
            ax.set_ylim(0, max(200, max(packet_counts) + 20))
            ax.set_title("NetPulse Monitor", color="#FFAA00", fontweight="bold")
            ax.set_xlabel("Time (last 30 sec)", color="#00FFFF")
            ax.set_ylabel("Packets/sec", color="#00FFFF")
            ax.tick_params(colors="#00FFFF")
            ax.set_facecolor("#1A1A1A")
            ax.legend(facecolor="#0D0D0D", edgecolor="#FF00FF", labelcolor="#00FFFF")
            canvas.draw()

        if progress:
            progress["value"] = (i + 1) * 100 / duration
            root.update_idletasks()

        time.sleep(1)

    print("Monitoring complete.")

# Run the GUI
def run_gui(model):
    root = tk.Tk()
    root.title("CyberPulse IDS")
    root.geometry("900x700")
    root.configure(bg="#0D0D0D")

    title_label = tk.Label(root, text="CyberPulse IDS", font=("Courier", 24, "bold"), fg="#FF00FF", bg="#0D0D0D")
    title_label.pack(pady=10)

    status_frame = tk.Frame(root, bg="#1A1A1A", bd=2, relief="groove", highlightbackground="#FFAA00", highlightthickness=2)
    status_frame.pack(pady=10, padx=20, fill="x")
    status_label = tk.Label(status_frame, text="Normal Traffic", font=("Courier", 18, "bold"), fg="#00FFFF", bg="#1A1A1A")
    status_label.pack(pady=5)

    attack_label = tk.Label(root, text="Attack: None", font=("Courier", 14), fg="#00FF00", bg="#0D0D0D")
    attack_label.pack(pady=5)

    graph_frame = tk.Frame(root, bg="#0D0D0D")
    graph_frame.pack(pady=10, padx=20, fill="both", expand=True)
    fig, ax = plt.subplots(figsize=(8, 4))
    fig.patch.set_facecolor("#0D0D0D")
    canvas = FigureCanvasTkAgg(fig, master=graph_frame)
    canvas.get_tk_widget().pack(fill="both", expand=True)

    style = ttk.Style()
    style.configure("Cyber.Horizontal.TProgressbar", troughcolor="#1A1A1A", background="#FF00FF", bordercolor="#00FFFF")
    progress = ttk.Progressbar(root, length=400, mode="determinate", style="Cyber.Horizontal.TProgressbar")
    progress.pack(pady=20)

    def update_gui():
        monitor_traffic(model, duration=90, label=status_label, attack_label=attack_label, canvas=canvas, ax=ax, root=root, progress=progress)
        root.quit()

    Thread(target=update_gui).start()
    root.protocol("WM_DELETE_WINDOW", root.quit)
    root.mainloop()

# Main function
def main():
    open("ids_log.txt", "w").close()
    training_data = collect_training_data(duration=20)
    print(f"Collected normal feature data: {training_data}")
    model = train_model(training_data)
    print("\nStarting real-time anomaly detection...")
    run_gui(model)

if __name__ == "__main__":
    try:
        main()
    except PermissionError:
        print("Error: Run this script with admin/root privileges to capture network packets.")
    except KeyboardInterrupt:
        print("\nStopped by user.")