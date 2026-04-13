import os
import json
import asyncio
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List

app = FastAPI(title="DevSecOps IDS API")

# Allow CORS for dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", "/app/logs/alerts.json")
BLOCKED_IPS_PATH = "/app/logs/blocked_ips.json"

def read_alerts():
    """Reads all alerts from the JSON log file."""
    if not os.path.exists(LOG_FILE_PATH):
        return []
    
    alerts = []
    with open(LOG_FILE_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return alerts

@app.get("/api/alerts")
def get_alerts():
    """History of all alerts"""
    return read_alerts()

@app.get("/api/stats")
def get_stats():
    """Generate stats for the dashboard charts"""
    alerts = read_alerts()
    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    top_attackers = {}
    timeline = {}
    blocked_ips = []
    
    if os.path.exists(BLOCKED_IPS_PATH):
        try:
            with open(BLOCKED_IPS_PATH, "r") as f:
                blocked_ips = json.load(f)
        except:
            pass

    for alert in alerts:
        sev = alert.get("severity", "LOW")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        src_ip = alert.get("src_ip")
        if src_ip:
            top_attackers[src_ip] = top_attackers.get(src_ip, 0) + 1
            
        timestamp = alert.get("timestamp")
        if timestamp and len(timestamp) >= 16:
            # Assumes ISO Format: 2026-04-12T13:36:23Z
            minute = timestamp[11:16]
            timeline[minute] = timeline.get(minute, 0) + 1

    # Sort top attackers
    sorted_attackers = sorted(top_attackers.items(), key=lambda x: x[1], reverse=True)[:5]
    
    # Sort timeline by chronological order (HH:MM strings sort naturally)
    sorted_timeline = [{"time": k, "count": v} for k, v in sorted(timeline.items())][-30:] # last 30 intervals
    
    return {
        "total_alerts": len(alerts),
        "severity_counts": severity_counts,
        "top_attackers": [{"ip": k, "count": v} for k, v in sorted_attackers],
        "timeline": sorted_timeline,
        "blocked_ips": blocked_ips
    }

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """Push new alerts and refreshed stats to connected clients in real-time"""
    await websocket.accept()
    
    last_pos = 0
    if os.path.exists(LOG_FILE_PATH):
        last_pos = os.path.getsize(LOG_FILE_PATH)
        
    try:
        while True:
            if os.path.exists(LOG_FILE_PATH):
                current_size = os.path.getsize(LOG_FILE_PATH)
                if current_size > last_pos:
                    # File grew, read new lines
                    with open(LOG_FILE_PATH, "r") as f:
                        f.seek(last_pos)
                        new_data = f.read()
                        last_pos = f.tell()
                        
                        # Gather all new alerts before emitting
                        lines = [line for line in new_data.strip().split("\n") if line]
                        
                        for idx, line in enumerate(lines):
                            try:
                                alert_data = json.loads(line)
                                payload = alert_data.copy()
                                payload["type"] = "update"
                                payload["alert"] = alert_data
                                if idx == len(lines) - 1:
                                    payload["stats"] = get_stats()
                                await websocket.send_json(payload)
                            except:
                                pass
                elif current_size < last_pos:
                    # File was rotated/cleared
                    last_pos = 0
                    
            await asyncio.sleep(1) # check file every second
            
    except Exception as e:
        print(f"WebSocket closed: {e}")
