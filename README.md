# DevSecOps-Driven Automated Intrusion Detection and Response Platform

This project is a complete enterprise-style DevSecOps security platform that builds upon a Python-based Network Intrusion Detection System (NIDS). The system features containerization, structured continuous logging, a REST API backend, real-time WebSocket communication, and a visually appealing SOC-style dashboard.

## 1. Project Architecture

The platform is designed in a modular, multi-tier architecture using Docker for isolation and reproducibility:

- **Detection Layer (IDS)**: Written in Python (Scapy). Sniffs packets on the network interface and detects malicious signatures, anomalous traffic volumes, and specific port profiling. Validates threats against the AbuseIPDB API and outputs structured JSON logs. Requires raw network access (`network_mode: "host"`).
- **Backend API Layer**: Built with FastAPI. This microservice parses the JSON log files created by the IDS and exposes standard REST endpoints (for statistical aggregation) and a WebSocket endpoint (for real-time streaming to the dashboard).
- **Presentation Layer (Dashboard)**: A sleek, dark-themed SOC UI built in vanilla HTML/CSS/JS (served by an Nginx container). This frontend pulls analytics and real-time alerts from the backend.
- **Orchestration & DevOps Layer**: All services are composed together using `docker-compose.yml`. A GitHub Actions CI/CD pipeline enables continuous integration and automated redeployment upon git pushes.

## 2. Directory Structure

```text
.
├── ids/
│   ├── IDS.py                 # Core packet detection system
│   ├── requirements.txt
│   ├── Dockerfile             # Container definition for the IDS
│   └── .env.example           # Environment variables template
├── backend/
│   ├── api.py                 # FastAPI system serving REST/WebSocket
│   ├── requirements.txt
│   └── Dockerfile             # Container definition for the Backend
├── dashboard/
│   ├── index.html             # Frontend UI structure
│   ├── style.css              # Custom Dark-themed styling
│   ├── app.js                 # Chart.js visualization and WebSocket handler
│   └── Dockerfile             # Container definition using Nginx
├── logs/                      # Bound volume container for JSON alerts
├── docker-compose.yml         # Container orchestration
├── .github/workflows/         
│   └── deploy.yml             # Auto-deployment tracking file
└── README.md                  
```

## 7. Deployment Instructions

### Prerequisites
- Docker and Docker Compose installed.
- An AbuseIPDB API key.

### Local Deployment
1. Navigate to the `ids/` directory and create your environment variables file:
   ```bash
   cp ids/.env.example ids/.env
   ```
2. Edit `ids/.env` and insert your actual `API_KEY`.
3. Launch the platform using docker-compose from the project root:
   ```bash
   # Add --build to ensure fresh images
   docker-compose up -d --build
   ```
4. Access the **Dashboard** at `http://localhost`.
5. The API is accessible at `http://localhost:8000/api/stats`.

### CI/CD Deployment
This project includes a `.github/workflows/deploy.yml`. 
To deploy to a production server automatically:
1. Add the following repository secrets to your GitHub repo:
   - `SERVER_HOST`: The IP of the destination server.
   - `SERVER_USER`: The SSH login username.
   - `SERVER_SSH_KEY`: The SSH Private Key.
2. Every push to the `main` branch will automatically pull the code and rebuild the containers on the target machine.

## 8. Testing Procedure

You can simulate attacks on your local machine to verify the IDS detects them and displays them on the Dashboard in real time.

**Preparation**: Open the dashboard (`http://localhost`) in a browser alongside your terminal.

**Test 1: Ping Floods (Traffic Anomaly)**
Run a continuous ping flood against localhost (or the server IP):
```bash
ping -f 127.0.0.1
# Or in Windows: ping -t 127.0.0.1
```
*Expected Result*: The IDS will tally traffic and flag an anomaly (High Traffic to IP) based on the `ANOMALY_THRESHOLD` variable.

**Test 2: Known Suspicious Port Activity**
Simulate a connection attempt on port 4444 or 31337 (Meterpreter/BackOrifice default ports):
```bash
# Using Netcat: Listen on the suspicious port
nc -lvnp 4444

# from another terminal, connect to it
nc 127.0.0.1 4444
```
*Expected Result*: A "Suspicious port usage" log entry will stream to the Dashboard.

**Test 3: NMAP Scan Simulation**
Perform an NMAP scan against the host:
```bash
nmap -p 1-5000 127.0.0.1
```
*Expected Result*: Both traffic anomaly and suspicious port triggers will be activated, populating the Alert table rapidly.

## 9. Security Improvements Implemented

1. **Structured Logging**: Replaced noisy console prints with parsed JSON logging to allow indexing and standardized parsing.
2. **Container Isolation**: Moving components into Docker containers restricts host access (except for the IDS running with specific Linux capabilities).
3. **Environment Variables Strategy**: Secrets such as API keys are entirely removed from version control constraints (`.env.example` -> `.env`).
4. **Threat Intelligence Layering**: Instead of hitting an external API for every packet, the IDS uses local heuristics first to determine if an API lookup is warranted, significantly saving bandwidth and preventing rate-limit blocks.

## 10. Limitations and Future Work

### Current Limitations
- **Host Network Requirement**: Scapy inside a container requires `network_mode: "host"` to monitor raw host interfaces, breaking pure network container isolation for the IDS node.
- **Persistence**: By default, logs write to a `.json` file. If the file grows enormously, there currently is no auto-rotation, and the FastAPI file reader might experience latency. 
- **Platform Capability**: Only supports analyzing IPv4/TCP layers securely right now.

### Future Work
- Integrate a robust SEIM structure (like an ELK stack - Elasticsearch, Logstash, Kibana) replacing the JSON text file and generic dashboard for larger scaling.
- Active Response Mode utilizing IPtables/UFW to automatically ban the attacker's IP upon a "CRITICAL" intelligence validation.
- Implement token-based Authentication (JWT) for the Dashboard and Backend APIs.
