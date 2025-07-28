import jinja2
import json
import os
import base64
from datetime import datetime
import pdfkit
import configparser
from collections import defaultdict

# --- Matplotlib Setup ---
# This is the fix:
# 1. Import the base matplotlib library.
# 2. Set the backend to 'Agg'. This is a non-interactive backend that is safe for threads.
# 3. Now import pyplot. The order is crucial.
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


def generate_pie_chart_image(severity_counts):
    """Generates a pie chart and returns it as a Base64 encoded string."""
    if not any(severity_counts.values()):
        return None

    labels = ['High', 'Medium', 'Low']
    sizes = [severity_counts.get(s, 0) for s in labels]
    colors = ['#c82333', '#ffc107', '#28a745']
    
    # Filter out zero-value slices to avoid display issues
    real_labels = [l for i, l in enumerate(labels) if sizes[i] > 0]
    real_sizes = [s for s in sizes if s > 0]
    real_colors = [c for i, c in enumerate(colors) if sizes[i] > 0]

    if not real_sizes:
        return None

    fig, ax = plt.subplots()
    ax.pie(real_sizes, labels=real_labels, colors=real_colors, autopct='%1.1f%%', startangle=90, textprops={'color': 'black'})
    ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    
    chart_path = os.path.join("reports", "chart.png")
    plt.savefig(chart_path, transparent=True)
    plt.close(fig)
    
    with open(chart_path, "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
    
    os.remove(chart_path) # Clean up the temporary file
    return f"data:image/png;base64,{encoded_string}"


def generate_report():
    """Generates a PDF and HTML report with an embedded chart image."""
    json_file = "suspicious_packets.json"
    if not os.path.exists(json_file) or os.stat(json_file).st_size == 0:
        msg = "No suspicious packets to report."
        print(msg)
        return msg

    try:
        with open(json_file, "r") as f:
            alerts = json.load(f)
    except json.JSONDecodeError as e:
        msg = f"Report generation failed: Log file is corrupted. Error: {e}"
        print(msg)
        return msg

    total_packets = sum(1 for _ in open("suspicious_packets.txt", "r")) if os.path.exists("suspicious_packets.txt") else 0
    
    severity_counts = defaultdict(int)
    for alert in alerts:
        severity_counts[alert.get("Severity", "Low")] += 1

    # Generate the chart image
    chart_image_b64 = generate_pie_chart_image(severity_counts)

    env = jinja2.Environment(loader=jinja2.FileSystemLoader("templates"))
    template = env.get_template("report_template.html")

    html_content = template.render(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_packets=total_packets,
        total_alerts=len(alerts),
        severity_counts=dict(severity_counts),
        chart_image=chart_image_b64,
        alerts=alerts
    )

    os.makedirs("reports", exist_ok=True)
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_path = os.path.join("reports", f"report_{timestamp_str}.html")
    pdf_path = os.path.join("reports", f"report_{timestamp_str}.pdf")

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    try:
        config = configparser.ConfigParser()
        config.read('config.ini')
        wkhtmltopdf_path = config.get('Paths', 'wkhtmltopdf_path', fallback=None)
        
        pdfkit_config = pdfkit.configuration(wkhtmltopdf=wkhtmltopdf_path) if wkhtmltopdf_path and os.path.exists(wkhtmltopdf_path) else None
        
        # Enable local file access is crucial for wkhtmltopdf to render images
        options = {"enable-local-file-access": ""}
        pdfkit.from_file(html_path, pdf_path, configuration=pdfkit_config, options=options)
        
        msg = f"Report saved to {pdf_path}"
        print(msg)
        return msg
    except Exception as e:
        msg = f"PDF generation failed. Check wkhtmltopdf path in config.ini. Error: {e}"
        print(msg)
        return msg
