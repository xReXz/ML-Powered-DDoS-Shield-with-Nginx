import time
import re
import redis
import numpy as np
from sklearn.ensemble import IsolationForest

# Connect to the Redis container
r = redis.Redis(host='ddos-redis', port=6379, db=0, decode_responses=True)

# Path to the shared Nginx access logs inside the container
LOG_FILE_PATH = "/var/log/nginx/access.log"

def parse_logs():
    """Parses Nginx logs and counts requests per IP in the last window."""
    ip_counts = {}
    try:
        with open(LOG_FILE_PATH, "r") as f:
            lines = f.readlines()
            
        # Extract IP addresses using Regex
        for line in lines:
            match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip = match.group(1)
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
    except FileNotFoundError:
        # If log file doesn't exist yet, return empty data
        pass
    return ip_counts

def run_ml_defense():
    print("[🧠 ML Engine] Analyzing traffic fingerprints...")
    ip_data = parse_logs()
    
    # 💡 INJECT FAKE TRAFFIC: Gives the ML model a baseline of "normal" users
    ip_data["192.168.1.99"] = 2   # Fake User A (Sent 2 requests)
    ip_data["192.168.1.150"] = 4  # Fake User B (Sent 4 requests)
    
    if len(ip_data) < 3:
        print("[🧠 ML Engine] Waiting for more unique IP traffic to build baseline...")
        return

    ips = list(ip_data.keys())
    features = np.array(list(ip_data.values())).reshape(-1, 1)

    # Initialize Isolation Forest anomaly detection
    model = IsolationForest(contamination=0.05, random_state=42)
    predictions = model.fit_predict(features)

    for idx, pred in enumerate(predictions):
        # If an IP's traffic volume is a massive outlier compared to the baseline
        if pred == -1 and features[idx][0] > 20: 
            bad_ip = ips[idx]
            # Skip banning our fake baseline IPs
            if bad_ip in ["192.168.1.99", "192.168.1.150"]:
                continue
                
            print(f"[🚨 ML SHIELD] Outlier Detected! Banning IP: {bad_ip} (Requests: {features[idx][0]})")
            # Store ban in Redis for 5 minutes (300 seconds)
            r.setex(f"ban:{bad_ip}", 300, "1")

if __name__ == "__main__":
    print("[🚀 ML Engine] DDoS Detection Service Started. Monitoring logs...")
    while True:
        run_ml_defense()
        time.sleep(10)  # Run evaluation every 10 seconds
