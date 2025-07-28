# 🛡️ Python-Based Intrusion Detection System (IDS)

A real-time **Intrusion Detection System (IDS)** developed during my cybersecurity internship at **Cyborts**. This system monitors network traffic, matches against custom detection rules, generates real-time alerts, and exports professional reports — all from a Python-powered dashboard.

---

## 🚀 Features

- 📡 **Live Packet Sniffing** using Scapy  
- 🧠 **Rule Matching Engine** (Custom flat-file rules)  
- 🎮 **Tkinter-Based GUI Dashboard**  
- 📊 **Live Protocol Distribution Charts**  
- 🔊 **Optional Audio Alerts** using Pygame  
- 📄 **Automated HTML + PDF Report Generation**  
- 🗂️ **Log Archiving with Timestamped Filenames**  
- ⚙️ **Configurable Network Interface & Archive Settings**

---

## 🧰 Requirements / Prerequisites

### ✅ Python Version
- Python **3.10 or higher** (Tested on 3.13)

### 📦 Python Libraries

**Key Libraries Used:**
- `scapy` – network packet capture  
- `matplotlib` – protocol visualization  
- `jinja2` – HTML report generation  
- `pdfkit` – convert HTML to PDF  
- `pygame` – sound notifications  
- `tkinter` – GUI (usually pre-installed)

### 🖥️ External Software

**📄 wkhtmltopdf** – Required for PDF generation  
🔗 [Download from official site](https://wkhtmltopdf.org/downloads.html)  
✅ Make sure it's added to your system's PATH.

---

## 📥 Clone the Repository

To get a local copy of this project, run the following command:

```bash
git clone https://github.com/ShariqFarooqDev/Python-Based-Intrusion-Detection-System.git
cd Python-Based-Intrusion-Detection-System
```

---

## 🧪 How to Run

Make sure you're in the project directory and execute:

```bash
python ids_gui.py
```

> The GUI will launch. Choose a network interface, start sniffing, and watch for alerts.  
> You can generate reports or archive logs from the GUI directly.

---

## 📁 Output

- 📊 Alerts are logged to `suspicious_packets.json`, `.txt`, and `.xlsx`
- 📄 Reports saved in `/reports/` folder as `Report_<timestamp>.html`
- 🗂️ Archived logs go to `/archive/` with timestamped filenames
- 📥 PDF exported if `wkhtmltopdf` is installed

---

## 🎯 Future Enhancements

- 🔐 ML-based anomaly detection  
- 🌍 IP geolocation and visualization  
- 📨 Email/SMS alert integration  
- 🔐 User authentication for GUI

---

## 🙏 Acknowledgements

Special thanks to **Cyborts** for providing this hands-on opportunity.  
This month-long internship helped me sharpen my Python, networking, and cybersecurity skills in a practical environment.

---

## 👨‍💻 Author

**Shariq Farooq**  
🎓 B.E. Computer Systems Engineering  
📍 Balochistan University of Engineering & Technology  
🔗 [LinkedIn](https://www.linkedin.com/in/shariq-farooq)  
💻 [GitHub](https://github.com/ShariqFarooqDev)

---

## 📃 License

MIT License – feel free to use and modify.
