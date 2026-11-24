import numpy as np
import pandas as pd

np.random.seed(42)

def generate_dataset():
    records = []

    # 1. Normal Baseline Traffic (400 flows: HTTPS web browsing, DNS lookups, SSH admin)
    for i in range(400):
        proto_choice = np.random.choice(["HTTPS", "DNS", "SSH"], p=[0.65, 0.25, 0.10])
        src_ip = f"192.168.64.{np.random.randint(10, 50)}"
        
        if proto_choice == "HTTPS":
            dst_ip = f"104.21.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
            dst_port = 443
            bytes_sent = int(np.random.normal(1800, 600))
            packet_count = np.random.randint(8, 35)
            interval_jitter = round(np.random.uniform(1.5, 18.0), 3)  # Human browsing is irregular
        elif proto_choice == "DNS":
            dst_ip = "1.1.1.1"
            dst_port = 53
            bytes_sent = int(np.random.normal(95, 20))
            packet_count = 2
            interval_jitter = round(np.random.uniform(0.5, 25.0), 3)
        else:  # SSH
            dst_ip = "192.168.64.2"
            dst_port = 22
            bytes_sent = int(np.random.normal(900, 250))
            packet_count = np.random.randint(10, 40)
            interval_jitter = round(np.random.uniform(0.2, 8.0), 3)

        records.append({
            "flow_id": f"FLOW-{1000+i}",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "bytes_sent": max(64, bytes_sent),
            "packet_count": packet_count,
            "interval_jitter_sec": interval_jitter,
            "ground_truth": "Normal"
        })

    # 2. Attack Pattern A: Malware C2 Beaconing (12 flows: tiny packets, robotic ~0.02s jitter)
    for i in range(12):
        records.append({
            "flow_id": f"FLOW-{2000+i}",
            "src_ip": "192.168.64.28",
            "dst_ip": "185.220.101.44",
            "dst_port": 8443,
            "bytes_sent": int(np.random.normal(128, 4)),
            "packet_count": 2,
            "interval_jitter_sec": round(np.random.uniform(0.01, 0.04), 3),
            "ground_truth": "C2_Beacon"
        })

    # 3. Attack Pattern B: Data Exfiltration Burst (6 flows: massive outbound byte spikes)
    for i in range(6):
        records.append({
            "flow_id": f"FLOW-{3000+i}",
            "src_ip": "192.168.64.15",
            "dst_ip": "45.33.32.156",
            "dst_port": 4444,
            "bytes_sent": int(np.random.normal(95000, 8000)),
            "packet_count": np.random.randint(350, 500),
            "interval_jitter_sec": round(np.random.uniform(0.05, 0.2), 3),
            "ground_truth": "Data_Exfiltration"
        })

    # 4. Attack Pattern C: DNS Tunneling (6 flows: oversized DNS payloads on Port 53)
    for i in range(6):
        records.append({
            "flow_id": f"FLOW-{4000+i}",
            "src_ip": "192.168.64.41",
            "dst_ip": "91.198.174.192",
            "dst_port": 53,
            "bytes_sent": int(np.random.normal(4200, 300)),
            "packet_count": np.random.randint(25, 45),
            "interval_jitter_sec": round(np.random.uniform(0.1, 0.4), 3),
            "ground_truth": "DNS_Tunneling"
        })

    df = pd.DataFrame(records).sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv("network_flows.csv", index=False)
    print(f"[+] Generated {len(df)} network flow records in 'network_flows.csv'.")

if __name__ == "__main__":
    generate_dataset()
