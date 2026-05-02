import os
import csv
import sqlite3
import zipfile
from datetime import datetime

LOGS_DIR = "logs"
DB_PATH  = os.path.join(LOGS_DIR, "honeypot.db")
JSON_LOG = os.path.join(LOGS_DIR, "attacks.json")
TEXT_LOG = os.path.join(LOGS_DIR, "attacks.log")
CSV_PATH = os.path.join(LOGS_DIR, "attacks.csv")

def export_db_to_csv():
    if not os.path.exists(DB_PATH):
        print("[!] No database found.")
        return False
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute("SELECT * FROM events ORDER BY id")
        cols   = [d[0] for d in cursor.description]
        rows   = cursor.fetchall()
    with open(CSV_PATH, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(cols)
        writer.writerows(rows)
    print(f"[+] CSV exported → {CSV_PATH}  ({len(rows)} rows)")
    return True

def build_zip():
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_name = f"honeypot_logs_{ts}.zip"
    files    = [JSON_LOG, TEXT_LOG, DB_PATH, CSV_PATH]

    export_db_to_csv()

    added = 0
    with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in files:
            if os.path.exists(path):
                zf.write(path, arcname=os.path.basename(path))
                print(f"[+] Added {os.path.basename(path)}")
                added += 1
            else:
                print(f"[-] Skipped (not found): {path}")

    if added == 0:
        os.remove(zip_name)
        print("[!] No log files found. Run the honeypot first.")
        return

    print(f"\n✔  Archive ready: {zip_name}")

if __name__ == "__main__":
    build_zip()

