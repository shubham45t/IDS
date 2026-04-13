import os
import json
import logging
import time
from datetime import datetime
from collections import defaultdict
import requests
from dotenv import load_dotenv
from scapy.all import sniff, IP, TCP

# Load environment variables
load_dotenv()

# Configuration reading with defaults
MALICIOUS_IPS = set(os.getenv("MALICIOUS_IPS", "192.168.1.100").split(","))
SUSPICIOUS_PORTS = set([int(p) for p in os.getenv("SUSPICIOUS_PORTS", "4444,31337").split(",")])
ANOMALY_THRESHOLD = int(os.getenv("ANOMALY_THRESHOLD", 10))
THREAT_API_URL = os.getenv("THREAT_API_URL", "https://api.abuseipdb.com/api/v2/check")
API_KEY = os.getenv("API_KEY", "")
LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", "/app/logs/alerts.json")
BLOCKED_IPS_PATH = "/app/logs/blocked_ips.json"

# Ensure log directory exists
os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)

class JSONFileLogger:
    def __init__(self, filepath):
        self.filepath = filepath
    
    def log(self, severity, message, attack_type, geo, src_ip, dst_ip, src_port=None, dst_port=None, details=None):
        """Append a structured JSON record to the file"""
        record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "severity": severity,
            "message": message,
            "attack_type": attack_type,
            "geo": geo,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "details": details or {}
        }
        
        # We append as a newline-delimited JSON so it's easier to tail
        try:
            with open(self.filepath, "a") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:
            print(f"[ERROR] failed to write to log file: {e}")

class NIDS:
    def __init__(self):
        self.ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)
        self.scanned_ports = defaultdict(set)
        self.geo_cache = {}
        self.blocked_ips = set()
        self.logger = JSONFileLogger(LOG_FILE_PATH)
        self._load_blocked_ips()
        
    def _load_blocked_ips(self):
        if os.path.exists(BLOCKED_IPS_PATH):
            try:
                with open(BLOCKED_IPS_PATH, "r") as f:
                    ips = json.load(f)
                    self.blocked_ips.update(ips)
            except Exception as e:
                print(f"[ERROR] failed to load blocked IPS: {e}")

    def get_geo(self, ip):
        """Lookup IP geolocation and cache result"""
        if ip in ("127.0.0.1", "localhost", "::1") or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            return "Local", "Local Network"
        if ip not in self.geo_cache:
            try:
                r = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
                self.geo_cache[ip] = (r.get("city", "Unknown"), r.get("country", "Unknown"))
            except Exception:
                self.geo_cache[ip] = ("Unknown", "Unknown")
        city, country = self.geo_cache[ip]
        if city == "Unknown" and country == "Unknown":
            return "Unknown", "Unknown"
        return f"{city}, {country}"

    def auto_block(self, ip):
        """Automatically block an attacking IP using iptables"""
        if ip in self.blocked_ips or ip in ("127.0.0.1", "localhost", "::1"):
            # Do not actually iptables drop localhost directly to avoid breaking internal services
            # But we can still log it. Real-world scenario wouldn't block loopback.
            if ip in ("127.0.0.1", "localhost", "::1") and ip not in self.blocked_ips:
                print(f"[🛡️ AUTO-RESPONSE] Simulated block for localhost ({ip})")
                self.blocked_ips.add(ip)
                return True
            return False
            
        try:
            os.system(f"iptables -A INPUT -s {ip} -j DROP")
            self.blocked_ips.add(ip)
            print(f"[🛡️ AUTO-RESPONSE] Blocked {ip} via iptables.")
            
            with open(BLOCKED_IPS_PATH, "w") as f:
                json.dump(list(self.blocked_ips), f)
            return True
        except Exception as e:
            print(f"[ERROR] Failed to block {ip}: {e}")
            return False

    def check_api(self, ip):
        """Check IP reputation using external API"""
        if not API_KEY:
            return False
            
        try:
            headers = {
                'Key': API_KEY,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90
            }
            response = requests.get(THREAT_API_URL, headers=headers, params=params, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("data", {}).get("abuseConfidenceScore", 0) > 50:
                    return True
        except Exception as e:
            print(f"[ERROR] API check failed: {e}")
        return False

    def trigger_alert(self, severity, message, attack_type, geo, src_ip, dst_ip, src_port=None, dst_port=None, reason=""):
        # Print to console
        print(f"[{severity}] {message} [{attack_type}] ({src_ip} -> {dst_ip}) Loc: {geo} - {reason}")
        # Log to structured JSON
        self.logger.log(
            severity=severity,
            message=message,
            attack_type=attack_type,
            geo=geo,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            details={"reason": reason}
        )

    def analyze_packet(self, packet):
        if not packet.haslayer(IP):
            return
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = None
        dst_port = None

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        # Flags
        local_detected = False
        api_verified = False
        reasons = []
        attack_type = "Unknown"

        # Local Detection Rules
        if src_ip in MALICIOUS_IPS or dst_ip in MALICIOUS_IPS:
            reasons.append(f"IP in blocklist")
            attack_type = "Malicious IP"
            local_detected = True

        if src_port in SUSPICIOUS_PORTS or dst_port in SUSPICIOUS_PORTS:
            reasons.append(f"Suspicious port usage")
            attack_type = "Suspicious Port"
            local_detected = True

        self.ip_counts[src_ip] += 1
        if self.ip_counts[src_ip] == ANOMALY_THRESHOLD:
            reasons.append("High traffic anomaly from IP")
            if attack_type == "Unknown":
                attack_type = "Brute Force / DoS"
            local_detected = True

        if dst_port:
            self.port_counts[dst_port] += 1
            if self.port_counts[dst_port] == ANOMALY_THRESHOLD:
                reasons.append("High traffic anomaly to port")
                if attack_type == "Unknown":
                    attack_type = "Brute Force / DoS"
                local_detected = True
                
            self.scanned_ports[src_ip].add(dst_port)
            if len(self.scanned_ports[src_ip]) == 20: # threshold mapping to port scan
                reasons.append("Port Scan detected")
                attack_type = "Port Scan"
                local_detected = True

        # API Verification & Alert Generation
        if local_detected:
            # Get Geo
            geo_info = self.get_geo(src_ip)
            if isinstance(geo_info, tuple):
                geo_str = f"{geo_info[0]}, {geo_info[1]}"
            else:
                geo_str = geo_info
                
            severity = "MEDIUM" if len(reasons) > 1 else "LOW"
            
            # Elevate severity if Port Scan
            if attack_type == "Port Scan":
                severity = "HIGH"
                
            # Threat API Verify
            if self.check_api(src_ip) or self.check_api(dst_ip):
                api_verified = True
                severity = "CRITICAL"
                reasons.append("AbuseIPDB score > 50")
                attack_type = "Malicious IP"

            self.trigger_alert(severity, "Threat Detected", attack_type, geo_str, src_ip, dst_ip, src_port, dst_port, ", ".join(reasons))
            
            # Auto-Response Block
            if severity in ("HIGH", "CRITICAL") or attack_type in ("Port Scan", "Brute Force / DoS"):
                self.auto_block(src_ip)

def start_nids():
    print("🚀 NIDS Started with DevSecOps logging & Auto-Response")
    print(f"Logging to: {LOG_FILE_PATH}")
    print("Press Ctrl+C to stop\n")
    nids = NIDS()
    sniff(prn=nids.analyze_packet, store=0)

if __name__ == "__main__":
    start_nids()
