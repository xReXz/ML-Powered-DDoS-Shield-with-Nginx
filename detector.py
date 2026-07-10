import time
import json
import os
import redis
import numpy as np
from sklearn.ensemble import IsolationForest

r = redis.Redis(host='redis', port=6379, decode_responses=True)
LOG_FILE = "/var/log/nginx/access.json"

def parse_logs():
    if not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) == 0:
        return {}

    ip_counts = {}
    with open(LOG_FILE, 'r') as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                ip = data['remote_addr']
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
            except Exception:
                continue
    return ip_counts

def run_ml_defense():
    print("[🧠 ML Engine] Analyzing traffic fingerprints...")
    ip_data = parse_logs()
    
    if len(ip_data) < 3:
        print("[🧠 ML Engine] Waiting for more unique IP traffic to build baseline...")
        return

    ips = list(ip_data.keys())
    features = np.array(list(ip_data.values())).reshape(-1, 1)

    model = IsolationForest(contamination=0.05, random_state=42)
    predictions = model.fit_predict(features)

    for idx, pred in enumerate(predictions):
        if pred == -1 and features[idx][0] > 50: 
            bad_ip = ips[idx]
            print(f"[🚨 ML SHIELD] Outlier Detected! Banning IP: {bad_ip} (Requests: {features[idx][0]})")
            r.setex(f"ban:{bad_ip}", 300, "1")

if __name__ == "__main__":
    time.sleep(5)
    while True:
        run_ml_defense()
        time.sleep(10)
