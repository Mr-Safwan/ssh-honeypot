"""
log_rotation.py — Auto-archives honeypot logs daily.
Run standalone:      python3 log_rotation.py
Or runs automatically when imported by main.py
"""

import os
import gzip
import shutil
import threading
import time
from datetime import datetime, timedelta

LOGS_DIR   = "logs"
ARCHIVE_DIR = os.path.join(LOGS_DIR, "archive")

# Files to rotate
LOG_FILES = [
    os.path.join(LOGS_DIR, "attacks.log"),
    os.path.join(LOGS_DIR, "attacks.json"),
]

# How many days to keep archives before deleting
KEEP_DAYS = 30


def rotate_logs():
    """
    Compresses current log files into logs/archive/YYYY-MM-DD/
    then starts fresh empty log files.
    """
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    date_str    = datetime.now().strftime("%Y-%m-%d")
    archive_dir = os.path.join(ARCHIVE_DIR, date_str)
    os.makedirs(archive_dir, exist_ok=True)

    rotated = []
    for log_path in LOG_FILES:
        if not os.path.exists(log_path):
            continue
        if os.path.getsize(log_path) == 0:
            continue

        filename    = os.path.basename(log_path)
        archive_path = os.path.join(archive_dir, filename + ".gz")

        # Compress log file into archive
        with open(log_path, "rb") as f_in:
            with gzip.open(archive_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)

        # Clear the original log file (start fresh)
        open(log_path, "w").close()

        size = os.path.getsize(archive_path)
        rotated.append(f"{filename} → {archive_path} ({size:,} bytes)")

    if rotated:
        print(f"\n[LOG ROTATION] {date_str}")
        for r in rotated:
            print(f"  ✔ {r}")
    else:
        print(f"[LOG ROTATION] Nothing to rotate.")

    # Clean up old archives beyond KEEP_DAYS
    cleanup_old_archives()


def cleanup_old_archives():
    """Delete archive folders older than KEEP_DAYS."""
    cutoff = datetime.now() - timedelta(days=KEEP_DAYS)
    if not os.path.exists(ARCHIVE_DIR):
        return
    for folder in os.listdir(ARCHIVE_DIR):
        folder_path = os.path.join(ARCHIVE_DIR, folder)
        try:
            folder_date = datetime.strptime(folder, "%Y-%m-%d")
            if folder_date < cutoff:
                shutil.rmtree(folder_path)
                print(f"  🗑  Deleted old archive: {folder}")
        except ValueError:
            pass  # Skip folders that don't match date format


def seconds_until_midnight():
    """Calculate seconds remaining until midnight."""
    now       = datetime.now()
    midnight  = (now + timedelta(days=1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    return (midnight - now).total_seconds()


def rotation_scheduler():
    """Background thread — rotates logs every day at midnight."""
    print(f"[LOG ROTATION] Scheduler started. Next rotation at midnight.")
    while True:
        wait = seconds_until_midnight()
        time.sleep(wait)
        rotate_logs()


def start_rotation_scheduler():
    """Start the background rotation thread — call this from main.py."""
    t = threading.Thread(target=rotation_scheduler, daemon=True)
    t.start()


def list_archives():
    """Print all archived log files."""
    if not os.path.exists(ARCHIVE_DIR):
        print("No archives found.")
        return
    folders = sorted(os.listdir(ARCHIVE_DIR))
    if not folders:
        print("No archives found.")
        return
    print(f"\n{'Date':<15} {'File':<30} {'Size':>10}")
    print("─" * 55)
    for folder in folders:
        folder_path = os.path.join(ARCHIVE_DIR, folder)
        for f in os.listdir(folder_path):
            size = os.path.getsize(os.path.join(folder_path, f))
            print(f"{folder:<15} {f:<30} {size:>8,} B")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Honeypot log rotation tool.")
    parser.add_argument("--rotate", action="store_true", help="Rotate logs now")
    parser.add_argument("--list",   action="store_true", help="List all archives")
    args = parser.parse_args()

    if args.list:
        list_archives()
    else:
        # Default action is rotate
        rotate_logs()
        print("\nArchived logs saved to logs/archive/")
