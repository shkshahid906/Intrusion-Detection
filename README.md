# SecureWatch IDS

A professional Intrusion Detection System (IDS) with real-time network analysis, alert management, and advanced dashboard visualization.

## Features
- Real-time network event monitoring and analytics
- Live dashboard with Socket.IO updates 
- Alert escalation and management
- Threat intelligence summary
- Network topology visualization
- Reporting and export features
- Modern, responsive UI (Plotly.js, D3.js)

## Technology Stack
- Python 3.13+
- Flask & Flask-SocketIO
- SQLAlchemy (SQLite backend)
- Plotly.js, D3.js (frontend)
- eventlet (for real-time WebSocket support)

## Project Structure
```
alert_manager.py           # Alert logic and escalation
app.py                     # Main Flask app and Socket.IO server
config.py                  # Configuration settings
network_capture.py         # Network event capture/simulation
reporting_manager.py       # Reporting and export logic
database_manager.py        # Database models and utilities
logging_manager.py         # Logging and audit trail
static/dashboard.js        # Frontend dashboard logic
templates/dashboard.html   # Main dashboard UI
requirements.txt           # Python dependencies
```

## Setup Instructions
1. **Clone the repository**
2. **Create a virtual environment**
   ```
   python -m venv .venv
   .venv\Scripts\activate  # On Windows
   source .venv/bin/activate  # On Linux/Mac
   ```
3. **Install dependencies**
   ```
   pip install -r requirements.txt
   ```
4. **Install eventlet for real-time support**
   ```
   pip install eventlet
   ```
5. **Run the application**
   ```
   python app.py
   ```
6. **Open your browser**
   - Go to [http://localhost:5000](http://localhost:5000)

## Usage
- Click "Start Monitoring" to begin capturing network events.
- View real-time events, analytics, alerts, and reports in the dashboard tabs.
- Use the alert management tab to acknowledge or resolve alerts.
- Use the network topology and threat intelligence tabs for advanced insights.

## Notes
- For real network capture, install and configure [scapy](https://scapy.net/).
- By default, the app runs in simulation mode if scapy is not available.
- For production, use a production-ready WSGI server (not Flask's built-in server).

## INTRUSION

├── alert_manager.py
├── app.py
├── config.py
├── database_manager.py
├── logging_manager.py
├── network_capture.py
├── reporting_manager.py
├── requirements.txt
├── static/
│   └── dashboard.js
├── templates/
│   └── dashboard.html