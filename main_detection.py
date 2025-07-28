import threading
from datetime import datetime
import csv
import json
import os
import queue
from scapy.all import sniff, IP
import configparser
from detection_logic import AlertEngine # <-- Uses the new module

# --- Global Variables & Setup ---
packet_count = 0
alert_count = 0
alert_queue = queue.Queue()
stop_sniffing_event = threading.Event()
active_connections = {}
CONNECTION_TIMEOUT = 300 # Default

def load_config():
    """Loads configuration from config.ini"""
    global CONNECTION_TIMEOUT
    config = configparser.ConfigParser()
    if os.path.exists('config.ini'):
        config.read('config.ini')
        CONNECTION_TIMEOUT = config.getint('Sniffer', 'connection_timeout', fallback=300)
    else:
        print("Warning: config.ini not found. Using default values.")

# --- Logging Functions ---
def log_to_file(filename, data_str):
    with open(filename, "a") as f:
        f.write(data_str + "\n")

def log_to_csv(alert):
    file_exists = os.path.isfile("suspicious_packets.csv")
    with open("suspicious_packets.csv", "a", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=alert.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(alert)

def log_to_json(alert):
    json_file = "suspicious_packets.json"
    alerts = []
    if os.path.exists(json_file) and os.stat(json_file).st_size != 0:
        with open(json_file, "r") as f:
            try:
                alerts = json.load(f)
            except json.JSONDecodeError:
                alerts = []
    alerts.append(alert)
    with open(json_file, "w") as f:
        json.dump(alerts, f, indent=4)

def queue_and_log(alert):
    """Puts an alert on the queue and logs it to all formats."""
    global alert_count
    alert_queue.put(alert)
    alert_count += 1
    log_str = f"ALERT: {alert['Time']} | {alert['Source']} -> {alert['Destination']} | Proto: {alert['Protocol']} | Sev: {alert['Severity']} | Msg: {alert['Message']}"
    log_to_file("suspicious_packets.txt", log_str)
    log_to_csv(alert)
    log_to_json(alert)

# --- Core Sniffing Logic ---
def get_active_connections():
    now = datetime.now()
    stale = [conn_id for conn_id, seen in active_connections.items() if (now - seen).total_seconds() > CONNECTION_TIMEOUT]
    for conn_id in stale:
        del active_connections[conn_id]
    return list(active_connections.keys())

def reset_stats():
    """Resets all counters and active connections."""
    global packet_count, alert_count, active_connections
    packet_count = 0
    alert_count = 0
    active_connections.clear()
    print("Statistics have been reset.")

def process_packet(alert_engine):
    """A wrapper function to be used by Scapy's sniff()."""
    def packet_callback(packet):
        global packet_count
        packet_count += 1

        # Update active connections
        if packet.haslayer(IP):
            conn_id = f"{packet[IP].src} -> {packet[IP].dst}"
            active_connections[conn_id] = datetime.now()
        
        # Check for alerts using the alert engine
        alert = alert_engine.check_packet(packet)
        if alert:
            queue_and_log(alert)
            
    return packet_callback

def start_sniffing(iface=None):
    """Initializes the alert engine and starts the sniffing loop."""
    global rules
    load_config()
    alert_engine = AlertEngine(rules_file="rules.txt")
    
    if not alert_engine.rules:
        alert_queue.put({"type": "status", "message": "Error: rules.txt not found or is empty. Stopping."})
        return

    status_message = f"Sniffing started on interface: {'all' if not iface else iface}"
    print(status_message)
    alert_queue.put({"type": "status", "message": status_message})
    
    stop_sniffing_event.clear()
    try:
        sniff(iface=iface, prn=process_packet(alert_engine), store=False, stop_filter=lambda x: stop_sniffing_event.is_set())
    except Exception as e:
        error_msg = f"Sniffing error: {e}"
        print(error_msg)
        alert_queue.put({"type": "status", "message": error_msg})

    print("Sniffing stopped.")
    alert_queue.put({"type": "status", "message": "Sniffing stopped."})
