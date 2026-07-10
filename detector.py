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
    """Parses Nginx logs and counts requests per IP."""
    ip_counts = {}
    try:
        with open(LOG_FILE_PATH, "r") as f:
            lines = f.readlines()
            
        print(f"[📋 Log Debug] Total raw lines found in access.log: {len(lines)}")
            
        for line in lines:
            # Grab the IP whether it's IPv4, IPv6 (::1), or Docker Gateway
            match = re.match(r'^(\S+)', line)
            if match:
                ip = match.group(1)
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
    except FileNotFoundError:
        print("[📋 Log Debug] access.log file not found yet. Waiting for first web request...")
        pass
    return ip_counts

def run_ml_defense():
    print("\n[🧠 ML Engine] Analyzing traffic fingerprints...")
    ip_data = parse_logs()
    
    if ip_data:
        print(f"[📋 Log Debug] Active IPs found in logs: {ip_data}")
    
    # Inject fake traffic baseline
    ip_data["192.168.1.99"] = 2   
    ip_data["192.168.1.150"] = 4  
    
    ips = list(ip_data.keys())
    features = np.array(list(ip_data.values())).reshape(-1, 1)

    # Initialize Isolation Forest anomaly detection
    model = IsolationForest(contamination=0.2, random_state=42)
    predictions = model.fit_predict(features)

    for idx, pred in enumerate(predictions):
        current_ip = ips[idx]
        request_count = features[idx][0]
        
        # Skip evaluating our fake baseline users
        if current_ip in ["192.168.1.99", "192.168.1.150"]:
            continue
            
        # BAN TRIGGER: If ML flags it as an anomaly OR if it exceeds 20 requests
        if pred == -1 or request_count > 20: 
            print(f"[🚨 ML SHIELD] Outlier Detected! Banning IP: {current_ip} (Requests: {request_count})")
            r.setex(f"ban:{current_ip}", 300, "1")

if __name__ == "__main__":
    print("[🚀 ML Engine] DDoS Detection Service Started. Monitoring logs...")
    while True:
        run_ml_defense()
        time.sleep(10)  # Evaluate every 10 seconds
