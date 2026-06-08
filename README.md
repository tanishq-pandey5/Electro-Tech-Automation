# Electrotech Automation - Smart SCADA Dashboard & PLC Database System

This directory contains the production-ready code files for the Electrotech Automation industrial website. The site integrates an interactive SCADA Dashboard simulation, operator control modal, database persistence, and automated SMTP email alerting.

---

## 📁 Project Directory Tree

The workspace consists of the following components:

```text
Electrotech Automation /
├── index.html       # Single-Page App (SPA) responsive industrial dashboard & SVG assets
├── server.py        # Multi-threaded Python HTTP Server, SQLite API router, & Simulator
├── scada.db         # Persistent SQLite database storing logs and settings (generated on boot)
└── README.md        # This configuration and startup guide
```

---

## 🚀 Getting Started

To run the fully database-integrated, interactive SCADA system locally:

1. **Open your Terminal** in this project directory:
   ```bash
   cd "/Users/tanishqpandey/Documents/Projects/Electrotech Automation "
   ```

2. **Launch the Server**:
   Start the unbuffered Python HTTP backend:
   ```bash
   python3 -u server.py
   ```

3. **Open the App**:
   Navigate to the following address in your browser:
   ```text
   http://localhost:8000/
   ```

---

## 🛠️ Key Operational Features

### 1. Interactive SCADA Panel
- **Start / Stop controls**: Ramp the machine speed up/down dynamically.
- **Vibration & Power dials**: Respond to actual speed in real-time.
- **Robotic Arm SVG Mimic**: swept-angle rotation synced to the actual RPM.
- **Oscilloscope Waveform**: Visualizes live temperature and pressure on a rolling Canvas sparkline.
- **Audit Console**: Outputs server timestamps and audit logs.

### 2. SQLite Database Logs
When running, the server continuously writes records to `scada.db`. Opening the website will query these logs to pre-populate charts and console histories automatically across restarts:
- Query telemetry logs: `sqlite3 scada.db "select * from telemetry_logs;"`
- Query system events: `sqlite3 scada.db "select * from event_logs;"`
- Query safety config: `sqlite3 scada.db "select * from configs;"`

### 3. SMTP Mail Connection Setup
To dispatch email notifications for critical line events:
1. Open the website, click **Open Live Operator Console** -> **Mail Setup** tab.
2. Enter your SMTP details (e.g. `smtp.gmail.com` on port `587` with `STARTTLS` encryption).
3. Provide your sender credentials (use an **App Password** for services like Gmail).
4. Enter the recipient email, toggle **Enable Email Alert Dispatch**, and click **Save Config**.
5. Test using the **Test Email** button. Alarms (like Hydraulic Pressure line drops or high temp warnings) will now automatically trigger email dispatches.

---

## 💻 Standalone Offline Mode
If you double-click `index.html` directly from the filesystem (without starting the Python server), the page **automatically activates a client-side simulator**. It remains fully animated and interactive, mocking the telemetry physics engine locally in your browser.
