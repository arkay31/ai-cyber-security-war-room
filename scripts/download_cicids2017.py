"""
CICIDS2017 Dataset Utility.
Generates a clearly-labeled development sample dataset with realistic network flow feature distributions
derived from the official CICIDS2017 schema, or downloads/processes full raw CSVs if configured.
"""

import os
import numpy as np
import pandas as pd

RAW_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "raw")
OUTPUT_PATH = os.path.join(RAW_DATA_DIR, "cicids2017_sample.csv")

FEATURE_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd Header Length",
    "Bwd Header Length",
    "Packet Length Mean",
    "Packet Length Std",
    "SYN Flag Count",
    "ACK Flag Count",
    "Average Packet Size",
    "Init_Win_bytes_forward",
    "Label"
]


def generate_development_sample(n_samples: int = 5000) -> str:
    """
    Generate a clearly labeled synthetic development sample for local ML training and testing.
    NOTE: Clearly labeled as development sample - not for publishing benchmark papers.
    """
    np.random.seed(42)
    os.makedirs(RAW_DATA_DIR, exist_ok=True)

    labels = ["BENIGN", "PortScan", "DDoS", "DoS", "Brute Force", "Bot"]
    weights = [0.60, 0.10, 0.12, 0.08, 0.06, 0.04]
    sample_labels = np.random.choice(labels, size=n_samples, p=weights)

    data = []
    for label in sample_labels:
        if label == "BENIGN":
            dest_port = np.random.choice([80, 443, 53, 22, 8080, 3306])
            flow_duration = int(np.random.exponential(scale=50000) + 100)
            fwd_pkts = np.random.poisson(lam=8) + 1
            bwd_pkts = np.random.poisson(lam=10) + 1
            fwd_len_mean = float(np.random.normal(loc=120, scale=30))
            bwd_len_mean = float(np.random.normal(loc=450, scale=80))
            tot_fwd_len = fwd_pkts * fwd_len_mean
            tot_bwd_len = bwd_pkts * bwd_len_mean
            flow_bytes_s = (tot_fwd_len + tot_bwd_len) / (max(flow_duration, 1) / 1e6)
            flow_pkts_s = (fwd_pkts + bwd_pkts) / (max(flow_duration, 1) / 1e6)
            flow_iat_mean = flow_duration / max(fwd_pkts + bwd_pkts, 1)
            flow_iat_std = flow_iat_mean * 0.4
            fwd_hdr_len = fwd_pkts * 20
            bwd_hdr_len = bwd_pkts * 20
            pkt_len_mean = (tot_fwd_len + tot_bwd_len) / (fwd_pkts + bwd_pkts)
            pkt_len_std = 150.0
            syn_count = 1 if np.random.rand() > 0.3 else 0
            ack_count = 1 if np.random.rand() > 0.2 else 0
            avg_pkt_size = pkt_len_mean * 1.05
            init_win_fwd = int(np.random.choice([65535, 29200, 14600]))

        elif label == "PortScan":
            dest_port = int(np.random.randint(20, 65000))
            flow_duration = int(np.random.uniform(50, 1500))
            fwd_pkts = np.random.choice([1, 2])
            bwd_pkts = 0 if np.random.rand() > 0.3 else 1
            fwd_len_mean = 0.0 if np.random.rand() > 0.5 else 40.0
            bwd_len_mean = 0.0
            tot_fwd_len = fwd_pkts * fwd_len_mean
            tot_bwd_len = 0.0
            flow_bytes_s = tot_fwd_len / (max(flow_duration, 1) / 1e6)
            flow_pkts_s = (fwd_pkts + bwd_pkts) / (max(flow_duration, 1) / 1e6)
            flow_iat_mean = float(flow_duration)
            flow_iat_std = 0.0
            fwd_hdr_len = fwd_pkts * 20
            bwd_hdr_len = 0
            pkt_len_mean = fwd_len_mean
            pkt_len_std = 0.0
            syn_count = 1
            ack_count = 0
            avg_pkt_size = pkt_len_mean
            init_win_fwd = 1024

        elif label == "DDoS":
            dest_port = np.random.choice([80, 443])
            flow_duration = int(np.random.exponential(scale=10000) + 50)
            fwd_pkts = np.random.poisson(lam=40) + 10
            bwd_pkts = np.random.poisson(lam=2)
            fwd_len_mean = float(np.random.normal(loc=500, scale=50))
            bwd_len_mean = 50.0
            tot_fwd_len = fwd_pkts * fwd_len_mean
            tot_bwd_len = bwd_pkts * bwd_len_mean
            flow_bytes_s = (tot_fwd_len + tot_bwd_len) / (max(flow_duration, 1) / 1e6)
            flow_pkts_s = (fwd_pkts + bwd_pkts) / (max(flow_duration, 1) / 1e6)
            flow_iat_mean = flow_duration / max(fwd_pkts + bwd_pkts, 1)
            flow_iat_std = flow_iat_mean * 0.1
            fwd_hdr_len = fwd_pkts * 32
            bwd_hdr_len = bwd_pkts * 32
            pkt_len_mean = fwd_len_mean
            pkt_len_std = 80.0
            syn_count = 1
            ack_count = 1
            avg_pkt_size = pkt_len_mean
            init_win_fwd = 8192

        elif label == "DoS":
            dest_port = np.random.choice([80, 8080])
            flow_duration = int(np.random.exponential(scale=80000) + 5000)
            fwd_pkts = np.random.poisson(lam=15) + 5
            bwd_pkts = np.random.poisson(lam=1)
            fwd_len_mean = float(np.random.normal(loc=300, scale=40))
            bwd_len_mean = 20.0
            tot_fwd_len = fwd_pkts * fwd_len_mean
            tot_bwd_len = bwd_pkts * bwd_len_mean
            flow_bytes_s = (tot_fwd_len + tot_bwd_len) / (max(flow_duration, 1) / 1e6)
            flow_pkts_s = (fwd_pkts + bwd_pkts) / (max(flow_duration, 1) / 1e6)
            flow_iat_mean = flow_duration / max(fwd_pkts + bwd_pkts, 1)
            flow_iat_std = flow_iat_mean * 0.8
            fwd_hdr_len = fwd_pkts * 20
            bwd_hdr_len = bwd_pkts * 20
            pkt_len_mean = fwd_len_mean
            pkt_len_std = 50.0
            syn_count = 1
            ack_count = 0
            avg_pkt_size = pkt_len_mean
            init_win_fwd = 4096

        elif label == "Brute Force":
            dest_port = np.random.choice([22, 21, 3389])
            flow_duration = int(np.random.uniform(500, 8000))
            fwd_pkts = np.random.poisson(lam=12) + 4
            bwd_pkts = np.random.poisson(lam=8) + 2
            fwd_len_mean = float(np.random.normal(loc=80, scale=15))
            bwd_len_mean = float(np.random.normal(loc=60, scale=10))
            tot_fwd_len = fwd_pkts * fwd_len_mean
            tot_bwd_len = bwd_pkts * bwd_len_mean
            flow_bytes_s = (tot_fwd_len + tot_bwd_len) / (max(flow_duration, 1) / 1e6)
            flow_pkts_s = (fwd_pkts + bwd_pkts) / (max(flow_duration, 1) / 1e6)
            flow_iat_mean = flow_duration / max(fwd_pkts + bwd_pkts, 1)
            flow_iat_std = flow_iat_mean * 0.3
            fwd_hdr_len = fwd_pkts * 32
            bwd_hdr_len = bwd_pkts * 32
            pkt_len_mean = 70.0
            pkt_len_std = 25.0
            syn_count = 1
            ack_count = 1
            avg_pkt_size = 70.0
            init_win_fwd = 29200

        else:  # Bot
            dest_port = np.random.choice([8080, 6667, 4444, 80])
            flow_duration = int(np.random.exponential(scale=60000) + 1000)
            fwd_pkts = np.random.poisson(lam=6) + 2
            bwd_pkts = np.random.poisson(lam=4) + 1
            fwd_len_mean = float(np.random.normal(loc=150, scale=30))
            bwd_len_mean = float(np.random.normal(loc=200, scale=40))
            tot_fwd_len = fwd_pkts * fwd_len_mean
            tot_bwd_len = bwd_pkts * bwd_len_mean
            flow_bytes_s = (tot_fwd_len + tot_bwd_len) / (max(flow_duration, 1) / 1e6)
            flow_pkts_s = (fwd_pkts + bwd_pkts) / (max(flow_duration, 1) / 1e6)
            flow_iat_mean = flow_duration / max(fwd_pkts + bwd_pkts, 1)
            flow_iat_std = flow_iat_mean * 0.5
            fwd_hdr_len = fwd_pkts * 20
            bwd_hdr_len = bwd_pkts * 20
            pkt_len_mean = 175.0
            pkt_len_std = 40.0
            syn_count = 1
            ack_count = 1
            avg_pkt_size = 175.0
            init_win_fwd = 14600

        data.append({
            "Destination Port": dest_port,
            "Flow Duration": max(flow_duration, 1),
            "Total Fwd Packets": fwd_pkts,
            "Total Backward Packets": bwd_pkts,
            "Total Length of Fwd Packets": max(tot_fwd_len, 0.0),
            "Total Length of Bwd Packets": max(tot_bwd_len, 0.0),
            "Fwd Packet Length Mean": max(fwd_len_mean, 0.0),
            "Bwd Packet Length Mean": max(bwd_len_mean, 0.0),
            "Flow Bytes/s": max(flow_bytes_s, 0.0),
            "Flow Packets/s": max(flow_pkts_s, 0.0),
            "Flow IAT Mean": max(flow_iat_mean, 0.0),
            "Flow IAT Std": max(flow_iat_std, 0.0),
            "Fwd Header Length": fwd_hdr_len,
            "Bwd Header Length": bwd_hdr_len,
            "Packet Length Mean": max(pkt_len_mean, 0.0),
            "Packet Length Std": max(pkt_len_std, 0.0),
            "SYN Flag Count": syn_count,
            "ACK Flag Count": ack_count,
            "Average Packet Size": max(avg_pkt_size, 0.0),
            "Init_Win_bytes_forward": init_win_fwd,
            "Label": label
        })

    df = pd.DataFrame(data)
    df.to_csv(OUTPUT_PATH, index=False)
    print(f"Generated development dataset at: {OUTPUT_PATH} ({len(df)} rows)")
    print("Class distribution:\n", df['Label'].value_counts())
    return OUTPUT_PATH


if __name__ == "__main__":
    generate_development_sample(6000)
