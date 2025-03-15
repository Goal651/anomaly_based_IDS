import time
import numpy as np
from scapy.all import sniff, IP, ICMP, send
from sklearn.ensemble import IsolationForest
import tkinter as tk
from tkinter import ttk
from threading import Thread
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from scipy.interpolate import make_interp_spline
import warnings
warnings.filterwarnings("ignore")  # Suppress Scapy warnings

# Global variables
packet_count = 0
packet_history = []

# Callback function to count packets
def packet_callback(packet):
    global packet_count
    packet_count += 1

# Collect "normal" traffic data
def collect_training_data(duration=20):
    global packet_count
    print(f"Collecting normal traffic data for {duration} seconds...")
    data = []
    
    for _ in range(duration):
        packet_count = 0
        sniff(prn=packet_callback, timeout=1)
        data.append([packet_count])
        time.sleep(1)
    
    filtered_data = [x for x in data if x[0] <= 100]
    if len(filtered_data) < len(data):
        print(f"Filtered out {len(data) - len(filtered_data)} outliers from training data.")
    return np.array(filtered_data)

# Train the anomaly detection model
def train_model(data):
    print("Training anomaly detection model...")
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(data)
    return model

# Simulate a stronger ping flood
def simulate_ping_flood(target="127.0.0.1", count=5000):
    print("\033[93mSimulating DDoS attack (ping flood)...\033[0m")
    packet = IP(dst=target)/ICMP()
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
    global packet_count, packet_history
    print(f"Monitoring traffic for {duration} seconds...")
    min_rate, max_rate = 3, 70
    
    for i in range(duration):
        packet_count = 0
        sniff(prn=packet_callback, timeout=1)
        packet_history.append(packet_count)
        if len(packet_history) > 30:
            packet_history.pop(0)
        
        current_rate = np.array([[packet_count]])
        prediction = model.predict(current_rate)
        is_anomaly = (prediction[0] == -1) or (current_rate[0][0] < min_rate or current_rate[0][0] > 90)
        
        if is_anomaly and current_rate[0][0] >= 3:
            msg = f"ALERT: Anomaly! {packet_count} packets/sec"
            print(f"\033[91m{msg}\033[0m")
            log_alert(msg)
            if label: 
                label.config(text=msg, fg="#FF00FF")
                label.after(100, lambda: label.config(fg="#FF00FF" if label["fg"] == "#00FFFF" else "#00FFFF"))
        else:
            msg = f"Normal: {packet_count} packets/sec"
            print(msg)
            if label: label.config(text=msg, fg="#00FFFF")
        
        # Update attack status and GUI flash
        if i == 45:
            if attack_label: attack_label.config(text="Attack: DDoS Active", fg="#FFAA00")
            if root: root.configure(bg="#1A0D2E")
            Thread(target=simulate_ping_flood).start()
        elif i == 50 and attack_label:
            attack_label.config(text="Attack: None", fg="#00FF00")
            if root: root.configure(bg="#0D0D0D")
        
        # Update graph every 2 sec with smooth curve or fallback
        if canvas and ax and i % 2 == 0:
            ax.clear()
            x = np.arange(len(packet_history))
            if len(packet_history) >= 4:  # Need at least 4 points for cubic spline
                x_smooth = np.linspace(x.min(), x.max(), 300)
                spline = make_interp_spline(x, packet_history, k=3)
                y_smooth = spline(x_smooth)
                ax.plot(x_smooth, y_smooth, label="Packets/sec", color="#00FFFF", linewidth=3, alpha=0.8)
            else:
                ax.plot(x, packet_history, label="Packets/sec", color="#00FFFF", linewidth=3, alpha=0.8)  # Fallback
            
            ax.axhline(y=max_rate, color="#FF00FF", linestyle="--", label="Threshold")
            ax.set_ylim(0, max(200, max(packet_history) + 20))
            ax.set_title("NetPulse Monitor", color="#FFAA00", fontweight="bold")
            ax.set_xlabel("Time (last 30 sec)", color="#00FFFF")
            ax.set_ylabel("Packets/sec", color="#00FFFF")
            ax.tick_params(axis="x", colors="#00FFFF")
            ax.tick_params(axis="y", colors="#00FFFF")
            ax.set_facecolor("#1A1A1A")
            ax.legend(facecolor="#0D0D0D", edgecolor="#FF00FF", labelcolor="#00FFFF")
            canvas.draw()
        
        # Update progress bar
        if progress:
            progress['value'] = (i + 1) * 100 / duration
            root.update_idletasks()
        
        time.sleep(1)
    
    print("Monitoring complete.")

# Run the enhanced GUI
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
    style.theme_use("default")
    style.configure("Cyber.Horizontal.TProgressbar", troughcolor="#1A1A1A", background="#FF00FF", bordercolor="#00FFFF")
    progress = ttk.Progressbar(root, length=400, mode="determinate", style="Cyber.Horizontal.TProgressbar")
    progress.pack(pady=20)

    def update_gui():
        monitor_traffic(model, duration=90, label=status_label, attack_label=attack_label, 
                       canvas=canvas, ax=ax, root=root, progress=progress)
        root.quit()

    Thread(target=update_gui).start()
    root.protocol("WM_DELETE_WINDOW", root.quit)
    root.mainloop()

# Main function
def main():
    open("ids_log.txt", "w").close()
    
    training_data = collect_training_data(duration=20)
    print(f"Collected normal packet rates: {training_data.flatten()}")

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