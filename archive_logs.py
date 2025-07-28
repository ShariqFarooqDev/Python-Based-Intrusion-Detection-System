import os
import shutil
from datetime import datetime, timedelta
import configparser
import logging

# --- Setup central logger ---
# This will log actions from this script to a file.
logging.basicConfig(
    filename='ids_actions.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def archive_logs():
    """Archives log files and cleans up old archives based on config."""
    config = configparser.ConfigParser()
    config.read('config.ini')
    retain_days = config.getint('Logging', 'retain_days', fallback=90)

    files_to_archive = ["suspicious_packets.txt", "suspicious_packets.csv", "suspicious_packets.json"]
    archive_path = os.path.join("archive", datetime.now().strftime("%Y-%m-%d"))
    os.makedirs(archive_path, exist_ok=True)

    moved_count = 0
    for file in files_to_archive:
        if os.path.exists(file):
            try:
                shutil.move(file, os.path.join(archive_path, file))
                logging.info(f"Archived log file: {file} to {archive_path}")
                moved_count += 1
            except Exception as e:
                logging.error(f"Error archiving {file}: {e}")

    if moved_count == 0:
        logging.info("Archiving complete. No new log files were found.")
    else:
        logging.info(f"Successfully archived {moved_count} log files.")

    # --- Log Retention/Cleanup Logic ---
    logging.info(f"Starting log cleanup: retaining archives for {retain_days} days...")
    base_archive_dir = "archive"
    deleted_count = 0
    if os.path.exists(base_archive_dir):
        for folder_name in os.listdir(base_archive_dir):
            folder_path = os.path.join(base_archive_dir, folder_name)
            if os.path.isdir(folder_path):
                try:
                    folder_date = datetime.strptime(folder_name, "%Y-%m-%d")
                    if folder_date < (datetime.now() - timedelta(days=retain_days)):
                        shutil.rmtree(folder_path)
                        logging.info(f"Deleted old archive: {folder_path}")
                        deleted_count += 1
                except ValueError:
                    continue # Skip non-date folders
                except Exception as e:
                    logging.error(f"Error during cleanup of {folder_name}: {e}")
    
    logging.info(f"Log cleanup complete. Deleted {deleted_count} old archive(s).")
    return "Log archiving and cleanup complete."
