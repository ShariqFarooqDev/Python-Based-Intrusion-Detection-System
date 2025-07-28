import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import configparser
import os
import subprocess
import sys
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from collections import defaultdict
from datetime import datetime, timedelta
from scapy.all import get_if_list

# Import functions from other modules
from generate_report import generate_report
from archive_logs import archive_logs
import main_detection

class IdsDashboard(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Python IDS Dashboard")
        self.geometry("900x900") # Adjusted initial size

        self.sniffer_thread = None
        self.is_sniffing = False
        self.is_running = True
        self.after_id = None

        self.gui_severity_counter = defaultdict(int)
        self.recent_alerts_display = []

        self.load_config()
        self.setup_theme()
        self.create_widgets()
        
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.process_queue()

    def load_config(self):
        self.config = configparser.ConfigParser()
        self.config.read('config.ini')
        self.schedule_day = self.config.getint('Scheduler', 'schedule_day', fallback=2)
        self.schedule_hour = self.config.getint('Scheduler', 'schedule_hour', fallback=22)
        self.last_scheduled_run = datetime.min

    def setup_theme(self):
        self.theme = {
            "bg": "#2b2b2b", "fg": "#cccccc", "btn_bg": "#3c3c3c",
            "btn_fg": "#ffffff", "highlight": "#555555", "chart_bg": "#2b2b2b",
            "chart_fg": "#cccccc", "tree_bg": "#3c3c3c", "tree_fg": "#ffffff", 
            "tree_heading_bg": "#4a4a4a", "tree_heading_fg": "#ffffff", 
            "border": "#4a4a4a", "status_bg": "#1e1e1e"
        }
        self.configure(bg=self.theme["bg"])
        
        style = ttk.Style(self)
        style.theme_use('default')
        style.configure("TLabelFrame", background=self.theme["bg"], bordercolor=self.theme["border"], relief="solid")
        style.configure("TLabelFrame.Label", foreground=self.theme["fg"], background=self.theme["bg"], font=("Segoe UI", 12, "bold"))
        style.configure("Treeview", background=self.theme["tree_bg"], foreground=self.theme["tree_fg"], fieldbackground=self.theme["tree_bg"], rowheight=25)
        style.map('Treeview', background=[('selected', self.theme["highlight"])])
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), background=self.theme["tree_heading_bg"], foreground=self.theme["tree_heading_fg"])
        style.configure("Vertical.TScrollbar", background=self.theme["btn_bg"], troughcolor=self.theme["bg"])

    def create_widgets(self):
        self.status_var = tk.StringVar(value="Ready. Select an interface and press Start.")
        status_bar = tk.Label(self, textvariable=self.status_var, bg=self.theme["status_bg"], fg=self.theme["fg"], relief="sunken", anchor="w", padx=10)
        status_bar.pack(side="bottom", fill="x")

        # --- Create a Canvas with a Scrollbar ---
        canvas = tk.Canvas(self, bg=self.theme["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview, style="Vertical.TScrollbar")
        self.scrollable_frame = tk.Frame(canvas, bg=self.theme["bg"])

        self.canvas_window = canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        
        def on_frame_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def on_canvas_configure(event):
            canvas.itemconfig(self.canvas_window, width=event.width)

        self.scrollable_frame.bind("<Configure>", on_frame_configure)
        canvas.bind("<Configure>", on_canvas_configure)

        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # --- Main Content Frame (now inside the scrollable area) ---
        main_frame = tk.Frame(self.scrollable_frame, bg=self.theme["bg"], padx=15, pady=15)
        main_frame.pack(fill="both", expand=True)
        main_frame.columnconfigure(0, weight=1)

        control_frame = tk.Frame(main_frame, bg=self.theme["bg"])
        control_frame.grid(row=0, column=0, sticky="ew", pady=(0, 15))
        control_frame.columnconfigure(1, weight=1)

        tk.Label(control_frame, text="Interface:", font=("Segoe UI", 10), bg=self.theme["bg"], fg=self.theme["fg"]).grid(row=0, column=0, padx=(0,5))
        self.iface_var = tk.StringVar(value="all")
        ifaces = ["all"] + get_if_list()
        self.iface_menu = ttk.OptionMenu(control_frame, self.iface_var, ifaces[0], *ifaces)
        self.iface_menu.grid(row=0, column=1, sticky="w")
        
        self.btn_start = tk.Button(control_frame, text="▶ Start", command=self.start_sniffing, bg="#27ae60", fg="white", font=("Segoe UI", 10, "bold"), relief="raised", bd=2)
        self.btn_start.grid(row=0, column=2, padx=5)
        self.btn_stop = tk.Button(control_frame, text="■ Stop", command=self.stop_sniffing, bg="#c0392b", fg="white", font=("Segoe UI", 10, "bold"), relief="raised", bd=2, state="disabled")
        self.btn_stop.grid(row=0, column=3, padx=5)
        self.btn_clear = tk.Button(control_frame, text="Clear Stats", command=self.clear_stats, bg=self.theme["btn_bg"], fg=self.theme["btn_fg"], font=("Segoe UI", 10, "bold"), relief="raised", bd=2)
        self.btn_clear.grid(row=0, column=4, padx=(20, 5))

        self.create_metrics_widgets(main_frame)
        self.create_connections_widgets(main_frame)
        self.create_alerts_widgets(main_frame)
        self.create_bottom_widgets(main_frame)

    def create_metrics_widgets(self, parent):
        metrics_frame = tk.Frame(parent, bg=self.theme["bg"])
        metrics_frame.grid(row=1, column=0, pady=5, sticky="ew")
        metrics_frame.columnconfigure([0, 1, 2], weight=1)
        
        self.labels = {}
        self.labels["packets"] = self.create_label(metrics_frame, "📦 Total Packets: 0", 0)
        self.labels["alerts"] = self.create_label(metrics_frame, "🚨 Total Alerts: 0", 1)
        self.labels["active_conns_count"] = self.create_label(metrics_frame, "🔗 Active Connections: 0", 2)
        
        severity_frame = tk.Frame(parent, bg=self.theme["bg"])
        severity_frame.grid(row=2, column=0, pady=5, sticky="ew")
        severity_frame.columnconfigure([0, 1, 2], weight=1)
        
        self.create_severity_widget(severity_frame, "#e74c3c", "High Alerts", "high_count", 0)
        self.create_severity_widget(severity_frame, "#f39c12", "Medium Alerts", "medium_count", 1)
        self.create_severity_widget(severity_frame, "#2ecc71", "Low Alerts", "low_count", 2)

    def create_connections_widgets(self, parent):
        frame = ttk.LabelFrame(parent, text="🔗 Live Connections")
        frame.grid(row=3, column=0, padx=5, pady=10, sticky="ew")
        frame.columnconfigure(0, weight=1)
        self.active_connections_listbox = tk.Listbox(frame, height=8, bg=self.theme["tree_bg"], fg=self.theme["tree_fg"], selectbackground=self.theme["highlight"], bd=0, font=("Consolas", 11))
        self.active_connections_listbox.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.active_connections_listbox.yview)
        scrollbar.grid(row=0, column=1, sticky="ns", pady=5)
        self.active_connections_listbox.config(yscrollcommand=scrollbar.set)

    def create_alerts_widgets(self, parent):
        frame = ttk.LabelFrame(parent, text="🚨 Recent Alerts")
        frame.grid(row=4, column=0, padx=5, pady=10, sticky="ew")
        frame.columnconfigure(0, weight=1)
        
        columns = ("time", "source", "destination", "protocol", "severity", "message")
        self.alerts_tree = ttk.Treeview(frame, columns=columns, show="headings", height=8)
        self.alerts_tree.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        headings = {"time": "Time", "source": "Source ", "destination": "Destination", "protocol": "Protocol", "severity": "Severity", "message": "Message"}
        widths = {"time": 80, "source": 120, "destination": 120, "protocol": 60, "severity": 80, "message": 250}
        for col, text in headings.items():
            self.alerts_tree.heading(col, text=text, anchor=tk.W)
            self.alerts_tree.column(col, width=widths[col], stretch=(col=="message"))

        self.alerts_tree.tag_configure("high", foreground="#e74c3c")
        self.alerts_tree.tag_configure("medium", foreground="#f39c12")
        self.alerts_tree.tag_configure("low", foreground="#2ecc71")
        
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.alerts_tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns", pady=5)
        self.alerts_tree.config(yscrollcommand=scrollbar.set)

    def create_bottom_widgets(self, parent):
        bottom_frame = tk.Frame(parent, bg=self.theme["bg"])
        bottom_frame.grid(row=5, column=0, pady=(20, 0), sticky="ew")
        bottom_frame.columnconfigure(0, weight=3)
        bottom_frame.columnconfigure(1, weight=2)
        
        fig, ax = plt.subplots(figsize=(4, 3.5))
        fig.patch.set_facecolor(self.theme["chart_bg"])
        ax.set_facecolor(self.theme["chart_bg"])
        self.pie_chart_elements = {"fig": fig, "ax": ax}
        self.pie_canvas = FigureCanvasTkAgg(fig, master=bottom_frame)
        self.pie_canvas.get_tk_widget().grid(row=0, column=0, sticky="nsew")
        
        button_frame = tk.Frame(bottom_frame, bg=self.theme["bg"])
        button_frame.grid(row=0, column=1, padx=(20, 0), sticky="nsew")
        button_frame.rowconfigure([0, 1, 2], weight=1)
        button_frame.columnconfigure(0, weight=1)
        
        btn_generate = tk.Button(button_frame, text="📄 Generate Report", command=self.run_generate_report, bg=self.theme["btn_bg"], fg=self.theme["btn_fg"], font=("Segoe UI", 12, "bold"), relief="raised", bd=2, padx=10, pady=5)
        btn_generate.grid(row=0, column=0, sticky="ew", padx=20, pady=(10, 5))
        btn_archive = tk.Button(button_frame, text="🗃️ Archive Logs", command=self.run_archive_logs, bg=self.theme["btn_bg"], fg=self.theme["btn_fg"], font=("Segoe UI", 12, "bold"), relief="raised", bd=2, padx=10, pady=5)
        btn_archive.grid(row=1, column=0, sticky="ew", padx=20, pady=5)
        btn_open_folder = tk.Button(button_frame, text="📂 Open Reports", command=self.open_report_folder, bg=self.theme["btn_bg"], fg=self.theme["btn_fg"], font=("Segoe UI", 12, "bold"), relief="raised", bd=2, padx=10, pady=5)
        btn_open_folder.grid(row=2, column=0, sticky="ew", padx=20, pady=(5, 10))

    def create_label(self, parent, text, col):
        label = tk.Label(parent, text=text, font=("Segoe UI", 13, "bold"), bg=self.theme["bg"], fg=self.theme["fg"])
        label.grid(row=0, column=col, padx=5, pady=5, sticky="w")
        return label

    def create_severity_widget(self, parent, color, text, key, col):
        frame = tk.Frame(parent, bg=self.theme["bg"])
        frame.grid(row=0, column=col, padx=5, pady=2, sticky="ew")
        canvas = tk.Canvas(frame, width=20, height=20, bg=self.theme["bg"], highlightthickness=0)
        canvas.create_oval(5, 5, 15, 15, fill=color, outline=color)
        canvas.grid(row=0, column=0, padx=(0, 5))
        tk.Label(frame, text=f"{text}:", font=("Segoe UI", 11), bg=self.theme["bg"], fg=self.theme["fg"]).grid(row=0, column=1, sticky="w")
        count_label = tk.Label(frame, text="0", font=("Segoe UI", 11, "bold"), bg=self.theme["bg"], fg=color)
        count_label.grid(row=0, column=2, sticky="e", padx=(5,0))
        self.labels[key] = count_label

    def start_sniffing(self):
        if self.is_sniffing: return
        self.is_sniffing = True
        self.update_status("Starting sniffer...")
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.iface_menu.config(state="disabled")
        iface = self.iface_var.get()
        iface = None if iface == "all" else iface
        self.sniffer_thread = threading.Thread(target=main_detection.start_sniffing, args=(iface,), daemon=True)
        self.sniffer_thread.start()

    def stop_sniffing(self):
        if not self.is_sniffing: return
        self.update_status("Stopping sniffer...")
        main_detection.stop_sniffing_event.set()
        self.is_sniffing = False
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.iface_menu.config(state="normal")

    def clear_stats(self):
        if messagebox.askyesno("Confirm Clear", "Are you sure you want to clear all statistics and alerts? This cannot be undone."):
            main_detection.reset_stats()
            self.gui_severity_counter.clear()
            self.recent_alerts_display.clear()
            self.update_gui_elements()
            self.update_status("All statistics and alerts have been cleared.")

    def run_generate_report(self):
        self.update_status("Generating report...")
        threading.Thread(target=lambda: self.update_status(generate_report()), daemon=True).start()

    def run_archive_logs(self):
        self.update_status("Archiving logs...")
        threading.Thread(target=lambda: self.update_status(archive_logs()), daemon=True).start()

    def open_report_folder(self):
        report_dir = "reports"
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)
            
        try:
            if sys.platform == "win32":
                os.startfile(report_dir)
            elif sys.platform == "darwin": # macOS
                subprocess.Popen(["open", report_dir])
            else: # Linux and other UNIX-like
                subprocess.Popen(["xdg-open", report_dir])
            self.update_status(f"Opened report folder: {os.path.abspath(report_dir)}")
        except Exception as e:
            self.update_status(f"Error opening report folder: {e}")

    def process_queue(self):
        try:
            while not main_detection.alert_queue.empty():
                item = main_detection.alert_queue.get_nowait()
                if item.get("type") == "status":
                    self.update_status(item["message"])
                else:
                    severity = item.get("Severity", "Low")
                    self.gui_severity_counter[severity] += 1
                    self.recent_alerts_display.insert(0, item)
                    self.recent_alerts_display = self.recent_alerts_display[:15]
            self.update_gui_elements()
            self.perform_scheduled_tasks()
        except Exception as e:
            print(f"Error in queue processing: {e}")
        
        if self.is_running:
            self.after_id = self.after(200, self.process_queue)

    def update_gui_elements(self):
        self.labels["packets"].config(text=f"📦 Total Packets: {main_detection.packet_count}")
        self.labels["alerts"].config(text=f"🚨 Total Alerts: {main_detection.alert_count}")
        for sev in ["High", "Medium", "Low"]:
            self.labels[f"{sev.lower()}_count"].config(text=f"{self.gui_severity_counter[sev]}")
        
        active_conns = main_detection.get_active_connections()
        self.labels["active_conns_count"].config(text=f"🔗 Active Connections: {len(active_conns)}")
        self.active_connections_listbox.delete(0, tk.END)
        for conn_str in active_conns:
            self.active_connections_listbox.insert(tk.END, conn_str)

        self.alerts_tree.delete(*self.alerts_tree.get_children())
        for alert in self.recent_alerts_display:
            self.alerts_tree.insert("", "end", values=(
                alert["Time"].split(' ')[1], alert["Source"], alert["Destination"],
                alert["Protocol"], alert["Severity"], alert["Message"]
            ), tags=(alert["Severity"].lower(),))
        self.update_pie_chart()

    def update_pie_chart(self):
        ax = self.pie_chart_elements["ax"]
        ax.clear()
        counts = [self.gui_severity_counter.get(s, 0) for s in ["High", "Medium", "Low"]]
        if sum(counts) == 0:
            ax.text(0.5, 0.5, "No alerts yet", ha='center', va='center', fontsize=14, color=self.theme["chart_fg"])
        else:
            ax.pie(counts, labels=["High", "Medium", "Low"], autopct="%1.1f%%",
                   colors=["#e74c3c", "#f39c12", "#2ecc71"], startangle=140,
                   textprops={'color': self.theme["chart_fg"]})
        ax.set_title("Alert Severity Distribution", color=self.theme["chart_fg"])
        self.pie_canvas.draw()
    
    def update_status(self, message):
        if message:
            self.status_var.set(message)

    def perform_scheduled_tasks(self):
        now = datetime.now()
        if now.weekday() == self.schedule_day and now.hour >= self.schedule_hour:
            current_week_start = now.date() - timedelta(days=now.date().weekday())
            last_run_week_start = self.last_scheduled_run.date() - timedelta(days=self.last_scheduled_run.date().weekday())
            if last_run_week_start < current_week_start:
                self.update_status("Performing weekly scheduled tasks...")
                self.run_generate_report()
                self.run_archive_logs()
                self.last_scheduled_run = now
                self.update_status("Weekly tasks complete.")

    def on_close(self):
        self.is_running = False
        if self.after_id:
            self.after_cancel(self.after_id)
        if self.is_sniffing:
            self.stop_sniffing()
        self.destroy()

if __name__ == "__main__":
    app = IdsDashboard()
    app.mainloop()
