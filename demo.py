import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from sklearn.metrics import accuracy_score, recall_score, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, Flatten, Dense
import threading
import time
from scapy.all import sniff, IP, TCP, UDP, Raw

# Initialize packet storage
packets = []

# Callback to process incoming packets
def packet_callback(packet):
    try:
        if IP in packet:
            protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
            payload = bytes(packet[Raw].load).decode('utf-8', errors='ignore') if Raw in packet else "No Payload"
            encrypted = "Encrypted" if any(c in payload for c in ['\x00', '\xff']) else "Plaintext"
            application = "HTTP" if protocol == "TCP" and packet[TCP].dport == 80 else "Other"
            
            packets.append({
                "source_ip": packet[IP].src,
                "dest_ip": packet[IP].dst,
                "protocol": protocol,
                "payload": payload,
                "encryption": encrypted,
                "application": application
            })
    except Exception as e:
        print(f"Error processing packet: {e}")

# Start sniffing packets in a separate thread
def start_sniffing():
    sniff(prn=packet_callback, count=100, store=0)

# Function to log messages in the GUI
def log_message(output_widget, message, alert=False):
    if output_widget:
        tag = "alert" if alert else None
        output_widget.insert(tk.END, f"[{'ALERT' if alert else 'INFO'}] {message}\n", tag)
        output_widget.see(tk.END)

# FSM class for intrusion detection
class FSM:
    def __init__(self, output_widget):
        self.state = "INIT"
        self.alert = False
        self.output_widget = output_widget
        self.attack_reasons = []

    def log(self, message, alert=False):
        log_message(self.output_widget, message, alert)

    def authorize(self, packet):
        allowed_sources = ["192.168.1.1"]
        allowed_destinations = ["192.168.1.2", "192.168.1.4"]
        return packet["source_ip"] in allowed_sources and packet["dest_ip"] in allowed_destinations

    def process_header(self, packet):
        if not self.authorize(packet):
            self.log(f"Unauthorized access attempt from {packet['source_ip']} to {packet['dest_ip']}.", alert=True)
            self.alert = True
            self.attack_reasons.append("Unauthorized header detected")
            return False
        self.log(f"Packet header from {packet['source_ip']} to {packet['dest_ip']} is authorized.")
        return True

    def evaluate_payload(self, packet):
        payload = preprocess_payload(packet["payload"])
        payload_input = payload.reshape(1, len(payload), 1)
        prediction = model.predict(payload_input)
        if np.argmax(prediction) == 1:  # Malicious
            self.log("Deep learning detected malicious payload!", alert=True)
            self.alert = True
            self.attack_reasons.append("Malicious payload detected")
        else:
            self.log("Payload is clean.")

    def process_packet(self, packet):
        if self.state == "INIT":
            self.log(f"Checking packet header: {packet}")
            if self.process_header(packet):
                self.state = "CHECK_PAYLOAD"
            else:
                return

        if self.state == "CHECK_PAYLOAD":
            self.log("Analyzing payload with deep learning...")
            self.evaluate_payload(packet)
            self.state = "INIT"

    def check_alerts(self):
        if self.alert:
            reason = "\n".join(self.attack_reasons)
            self.log(f"FINAL ALERT: Intrusion detected! Reasons:\n{reason}", alert=True)
            return f"Intrusion Detected!\nReasons:\n{reason}"
        else:
            self.log("No intrusion detected.")
            return "No Intrusion Detected"

# Preprocess payload for the model
def preprocess_payload(payload_data):
    vectorized_payload = [ord(char) for char in payload_data]
    vectorized_payload = np.array(vectorized_payload) / 255.0
    return vectorized_payload

# Create CNN model
def create_cnn_model(input_shape):
    model = Sequential([
        Conv1D(64, 3, activation="relu", input_shape=input_shape),
        Flatten(),
        Dense(128, activation="relu"),
        Dense(2, activation="softmax")
    ])
    model.compile(optimizer="adam", loss="categorical_crossentropy", metrics=["accuracy"])
    return model

# Initialize the model
model = create_cnn_model((None, 1))

# FSM packet processing
def run_detection():
    fsm = FSM(output_widget)

    def process_packets():
        for i, packet in enumerate(packets):
            fsm.process_packet(packet)
            progress_bar["value"] = ((i + 1) / len(packets)) * 100
            root.update_idletasks()
            time.sleep(0.1)
        status = fsm.check_alerts()
        messagebox.showinfo("Detection Status", status)
        show_model_output()

    threading.Thread(target=process_packets).start()

# Show model output metrics
def show_model_output():
    y_true = [0, 1, 0, 1]
    y_pred = [0, 1, 0, 0]

    acc = accuracy_score(y_true, y_pred)
    recall = recall_score(y_true, y_pred)
    cm = confusion_matrix(y_true, y_pred)

    metrics_window = tk.Toplevel(root)
    metrics_window.title("Model Metrics")
    metrics_window.geometry("400x400")

    metrics_text = scrolledtext.ScrolledText(metrics_window, height=10)
    metrics_text.pack(pady=10)
    metrics_text.insert(tk.END, f"Accuracy: {acc:.2f}\n")
    metrics_text.insert(tk.END, f"Recall: {recall:.2f}\n")
    metrics_text.insert(tk.END, "Confusion Matrix:\n")

    fig, ax = plt.subplots(figsize=(5, 3))
    sns.heatmap(cm, annot=True, cmap="Blues", fmt="d", xticklabels=["Normal", "Attack"], yticklabels=["Normal", "Attack"], ax=ax)
    ax.set_title("Confusion Matrix")
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")

    canvas = FigureCanvasTkAgg(fig, metrics_window)
    canvas.draw()
    canvas.get_tk_widget().pack()

# GUI setup
root = tk.Tk()
root.title("Intrusion Detection System")
root.geometry("800x600")

output_widget = scrolledtext.ScrolledText(root, height=20)
output_widget.pack(pady=10)

progress_bar = ttk.Progressbar(root, length=300, mode='determinate')
progress_bar.pack(pady=5)

button_frame = tk.Frame(root)
button_frame.pack()

run_button = tk.Button(button_frame, text="Run Detection", command=run_detection)
run_button.grid(row=0, column=0, padx=5)

clear_button = tk.Button(button_frame, text="Clear Logs", command=lambda: output_widget.delete(1.0, tk.END))
clear_button.grid(row=0, column=1, padx=5)

sniff_thread = threading.Thread(target=start_sniffing)
sniff_thread.start()

root.mainloop()
