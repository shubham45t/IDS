FROM python:3.10-slim

# Install system dependencies required for scapy
# Set libpcap for network sniffing
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY IDS.py .

# We need elevated privileges to sniff packets (usually handled via docker-compose)
CMD ["python", "-u", "IDS.py"]
