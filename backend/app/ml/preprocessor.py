import re
from typing import List, Dict, Any, Tuple
import numpy as np
import pandas as pd

SELECTED_FEATURES: List[str] = [
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
    "Init_Win_bytes_forward"
]

# Mapping standard/variation labels to canonical attack types
LABEL_MAPPING: Dict[str, str] = {
    "BENIGN": "BENIGN",
    "PortScan": "PortScan",
    "DDoS": "DDoS",
    "DoS": "DoS",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "FTP-Patator": "Brute Force",
    "SSH-Patator": "Brute Force",
    "Brute Force": "Brute Force",
    "Bot": "Bot",
    "Web Attack – Brute Force": "Web Attack",
    "Web Attack – XSS": "Web Attack",
    "Web Attack – Sql Injection": "Web Attack",
    "Web Attack": "Web Attack",
    "Infiltration": "Infiltration",
}


class CICIDSPreprocessor:
    @staticmethod
    def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
        """Clean DataFrame: strip headers, drop duplicates, handle inf/nan."""
        # Clean column names (CICIDS2017 often has leading/trailing whitespaces)
        df.columns = [col.strip() for col in df.columns]

        # Drop duplicate records
        df = df.drop_duplicates()

        # Handle infinities and NaNs
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.fillna(0.0)

        # Standardize labels if Label column is present
        if "Label" in df.columns:
            df["Label"] = df["Label"].astype(str).str.strip()
            df["Clean_Label"] = df["Label"].map(lambda x: LABEL_MAPPING.get(x, "Other"))
        return df

    @staticmethod
    def extract_features_and_labels(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
        """Extract selected features and cleaned target labels."""
        df_clean = CICIDSPreprocessor.clean_dataframe(df)

        available_features = [col for col in SELECTED_FEATURES if col in df_clean.columns]
        missing_features = [col for col in SELECTED_FEATURES if col not in df_clean.columns]
        for col in missing_features:
            df_clean[col] = 0.0

        X = df_clean[SELECTED_FEATURES].astype(np.float32)
        y = df_clean["Clean_Label"] if "Clean_Label" in df_clean.columns else None
        return X, y

    @staticmethod
    def event_to_features(event: Dict[str, Any]) -> np.ndarray:
        """
        Convert an incoming security event JSON dictionary into a feature vector for inference.
        Uses raw_data fields if present, else derives sensible defaults from event fields.
        """
        raw = event.get("raw_data") or {}
        dest_port = float(event.get("destination_port") or raw.get("Destination Port") or raw.get("dest_port") or 80)
        flow_duration = float(raw.get("Flow Duration") or raw.get("flow_duration") or 1000.0)
        tot_fwd_pkts = float(raw.get("Total Fwd Packets") or raw.get("fwd_packets") or 5.0)
        tot_bwd_pkts = float(raw.get("Total Backward Packets") or raw.get("bwd_packets") or 4.0)
        tot_fwd_len = float(raw.get("Total Length of Fwd Packets") or 250.0)
        tot_bwd_len = float(raw.get("Total Length of Bwd Packets") or 300.0)
        fwd_len_mean = float(raw.get("Fwd Packet Length Mean") or (tot_fwd_len / max(tot_fwd_pkts, 1)))
        bwd_len_mean = float(raw.get("Bwd Packet Length Mean") or (tot_bwd_len / max(tot_bwd_pkts, 1)))
        flow_bytes_s = float(raw.get("Flow Bytes/s") or ((tot_fwd_len + tot_bwd_len) / (max(flow_duration, 1) / 1e6)))
        flow_pkts_s = float(raw.get("Flow Packets/s") or ((tot_fwd_pkts + tot_bwd_pkts) / (max(flow_duration, 1) / 1e6)))
        flow_iat_mean = float(raw.get("Flow IAT Mean") or (flow_duration / max(tot_fwd_pkts + tot_bwd_pkts, 1)))
        flow_iat_std = float(raw.get("Flow IAT Std") or 50.0)
        fwd_hdr_len = float(raw.get("Fwd Header Length") or (tot_fwd_pkts * 20.0))
        bwd_hdr_len = float(raw.get("Bwd Header Length") or (tot_bwd_pkts * 20.0))
        pkt_len_mean = float(raw.get("Packet Length Mean") or ((tot_fwd_len + tot_bwd_len) / max(tot_fwd_pkts + tot_bwd_pkts, 1)))
        pkt_len_std = float(raw.get("Packet Length Std") or 25.0)
        syn_count = float(raw.get("SYN Flag Count") or (1.0 if event.get("event_type") in ["port_scan", "failed_login"] else 0.0))
        ack_count = float(raw.get("ACK Flag Count") or 1.0)
        avg_pkt_size = float(raw.get("Average Packet Size") or pkt_len_mean)
        init_win_fwd = float(raw.get("Init_Win_bytes_forward") or 29200.0)

        feature_vector = np.array([
            dest_port,
            flow_duration,
            tot_fwd_pkts,
            tot_bwd_pkts,
            tot_fwd_len,
            tot_bwd_len,
            fwd_len_mean,
            bwd_len_mean,
            flow_bytes_s,
            flow_pkts_s,
            flow_iat_mean,
            flow_iat_std,
            fwd_hdr_len,
            bwd_hdr_len,
            pkt_len_mean,
            pkt_len_std,
            syn_count,
            ack_count,
            avg_pkt_size,
            init_win_fwd
        ], dtype=np.float32).reshape(1, -1)

        return feature_vector
