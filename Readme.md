A lightweight SSH honeypot built in Python that captures and logs 
unauthorized access attempts in real time.

## Features
- Fake SSH banner to lure attackers
- Captures login credentials (username & password)
- Logs attacker commands with fake shell responses
- GeoIP lookup on every connecting IP
- Structured JSON + human-readable logging
- SQLite database storage
- Web dashboard for visual monitoring
- Rate limiting per IP
- Log export to ZIP archive

## Project Structure
honeypot-project/
├── main.py          # Honeypot server
├── dashboard.py     # Web dashboard
├── export_logs.py   # Log exporter
└── logs/            # Generated at runtime


## Requirements
bash
pip install requests flask


## Usage

### Run the honeypot
bash
python3 main.py


### View web dashboard
bash
python3 dashboard.py
# Open http://localhost:5000

### Export logs
bash
python3 export_logs.py


## Dashboard
Shows real-time stats including:
- Total events, unique IPs, login attempts
- Top attacking IPs
- Most common passwords tried
- Full event log table

## Legal Notice
This tool is intended for educational purposes and 
authorized security research only. Only deploy on 
systems you own or have permission to monitor.

## Author
Mr-Safwan
