import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

def classify_threat_signature(row):
    if row["dst_port"] == 53 and row["bytes_sent"] > 1000:
        return "Suspected DNS Tunneling (Oversized Port 53 Payload)"
    elif row["bytes_sent"] > 50000:
        return "Suspected Data Exfiltration (High Outbound Volume)"
    elif row["interval_jitter_sec"] < 0.1 and row["bytes_sent"] < 300:
        return "Suspected C2 Malware Beaconing (Robotic Low-Jitter Heartbeat)"
    return "Anomalous Network Behaviour (Unusual Port/Flow Profile)"

def run_anomaly_detection():
    print("=" * 74)
    print("[ML-IDS] Network Anomaly & C2 Beacon Detector (Isolation Forest)")
    print("=" * 74)

    df = pd.read_csv("network_flows.csv")

    # Feature Engineering for Security Analytics
    df["bytes_per_packet"] = df["bytes_sent"] / df["packet_count"]
    df["log_jitter"] = np.log1p(df["interval_jitter_sec"])

    features = ["dst_port", "bytes_sent", "packet_count", "bytes_per_packet", "log_jitter"]
    X = df[features]

    # Standardize features so high byte counts do not dominate low jitter values
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train Unsupervised Isolation Forest (contamination ~ 5.6% expected anomalies)
    model = IsolationForest(n_estimators=150, contamination=0.056, random_state=42)
    df["prediction"] = model.fit_predict(X_scaled)
    df["anomaly_score"] = model.decision_function(X_scaled).round(4)

    # Isolation Forest outputs -1 for anomalies and 1 for normal flows
    anomalies = df[df["prediction"] == -1].copy()
    anomalies["threat_assessment"] = anomalies.apply(classify_threat_signature, axis=1)

    print(f"\n[+] Total Flows Analyzed:      {len(df)}")
    print(f"[+] Normal Baseline Flows:     {len(df[df['prediction'] == 1])}")
    print(f"[!] Anomalous Flows Flagged:   {len(anomalies)}")

    # Evaluate Detection Precision against Ground Truth
    true_positives = len(anomalies[anomalies["ground_truth"] != "Normal"])
    precision = (true_positives / len(anomalies)) * 100 if len(anomalies) > 0 else 0
    print(f"[+] Detection Precision:       {precision:.1f}% ({true_positives}/{len(anomalies)} confirmed threats)\n")

    print("-" * 74)
    print("[ALERT] SOC INCIDENT TRIAGE REPORT (TOP ANOMALIES BY SEVERITY)")
    print("-" * 74)

    top_alerts = anomalies.sort_values(by="anomaly_score").head(12)
    for _, row in top_alerts.iterrows():
        print(
            f"[{row['flow_id']}] {row['src_ip']} -> {row['dst_ip']}:{row['dst_port']} | "
            f"Bytes: {row['bytes_sent']} | Jitter: {row['interval_jitter_sec']}s | "
            f"Score: {row['anomaly_score']}"
        )
        print(f"   +-- Assessment: {row['threat_assessment']}")

    print("\n" + "=" * 74)
    print("[ACTION] RECOMMENDED SOC CONTAINMENT STEPS")
    print("=" * 74)
    suspicious_ips = anomalies[anomalies["ground_truth"] != "Normal"]["src_ip"].unique()
    for ip in suspicious_ips:
        print(f" - Isolate internal host {ip} for endpoint malware triage & memory capture.")
    print(" - Block outbound connections to flagged external C2/exfiltration IPs at UFW/firewall.")

if __name__ == "__main__":
    run_anomaly_detection()
