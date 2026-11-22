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


FEATURE_BOUNDS: Dict[str, Dict[str, Any]] = {
    "Destination Port": {"min": 0.0, "max": 65535.0, "default": 80.0, "unit": "port"},
    "Flow Duration": {"min": 0.0, "max": 120_000_000.0, "default": 1000.0, "unit": "microseconds"},
    "Total Fwd Packets": {"min": 1.0, "max": 10_000_000.0, "default": 5.0, "unit": "packets"},
    "Total Backward Packets": {"min": 0.0, "max": 10_000_000.0, "default": 4.0, "unit": "packets"},
    "Total Length of Fwd Packets": {"min": 0.0, "max": 100_000_000.0, "default": 250.0, "unit": "bytes"},
    "Total Length of Bwd Packets": {"min": 0.0, "max": 100_000_000.0, "default": 300.0, "unit": "bytes"},
    "Fwd Packet Length Mean": {"min": 0.0, "max": 65535.0, "default": 50.0, "unit": "bytes"},
    "Bwd Packet Length Mean": {"min": 0.0, "max": 65535.0, "default": 75.0, "unit": "bytes"},
    "Flow Bytes/s": {"min": 0.0, "max": 1_000_000_000.0, "default": 550.0, "unit": "bytes/sec"},
    "Flow Packets/s": {"min": 0.0, "max": 10_000_000.0, "default": 9.0, "unit": "packets/sec"},
    "Flow IAT Mean": {"min": 0.0, "max": 120_000_000.0, "default": 111.0, "unit": "microseconds"},
    "Flow IAT Std": {"min": 0.0, "max": 120_000_000.0, "default": 50.0, "unit": "microseconds"},
    "Fwd Header Length": {"min": 0.0, "max": 10_000_000.0, "default": 100.0, "unit": "bytes"},
    "Bwd Header Length": {"min": 0.0, "max": 10_000_000.0, "default": 80.0, "unit": "bytes"},
    "Packet Length Mean": {"min": 0.0, "max": 65535.0, "default": 61.0, "unit": "bytes"},
    "Packet Length Std": {"min": 0.0, "max": 65535.0, "default": 25.0, "unit": "bytes"},
    "SYN Flag Count": {"min": 0.0, "max": 1.0, "default": 0.0, "unit": "count"},
    "ACK Flag Count": {"min": 0.0, "max": 1.0, "default": 1.0, "unit": "count"},
    "Average Packet Size": {"min": 0.0, "max": 65535.0, "default": 61.0, "unit": "bytes"},
    "Init_Win_bytes_forward": {"min": -1.0, "max": 65535.0, "default": 29200.0, "unit": "bytes"},
}


class CICIDSPreprocessor:
    @staticmethod
    def sanitize_float(val: Any, default: float, min_val: float = 0.0, max_val: float = float("inf")) -> float:
        """Safely coerce any numeric representation to a bounded float without throwing."""
        if val is None:
            return default
        try:
            f = float(val)
            if np.isnan(f) or np.isinf(f):
                return default
            return float(np.clip(f, min_val, max_val))
        except (ValueError, TypeError):
            return default
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
        Applies strict bounds validation and sanitization for zero-failure inference.
        """
        raw = event.get("raw_data") or {}
        sf = CICIDSPreprocessor.sanitize_float

        dest_port = sf(
            event.get("destination_port") or raw.get("Destination Port") or raw.get("dest_port"),
            default=80.0, min_val=0.0, max_val=65535.0
        )
        flow_duration = sf(
            raw.get("Flow Duration") or raw.get("flow_duration"),
            default=1000.0, min_val=0.0, max_val=120_000_000.0
        )
        tot_fwd_pkts = sf(
            raw.get("Total Fwd Packets") or raw.get("fwd_packets"),
            default=5.0, min_val=1.0, max_val=10_000_000.0
        )
        tot_bwd_pkts = sf(
            raw.get("Total Backward Packets") or raw.get("bwd_packets"),
            default=4.0, min_val=0.0, max_val=10_000_000.0
        )
        tot_fwd_len = sf(
            raw.get("Total Length of Fwd Packets"),
            default=250.0, min_val=0.0, max_val=100_000_000.0
        )
        tot_bwd_len = sf(
            raw.get("Total Length of Bwd Packets"),
            default=300.0, min_val=0.0, max_val=100_000_000.0
        )
        fwd_len_mean = sf(
            raw.get("Fwd Packet Length Mean"),
            default=(tot_fwd_len / max(tot_fwd_pkts, 1.0)), min_val=0.0, max_val=65535.0
        )
        bwd_len_mean = sf(
            raw.get("Bwd Packet Length Mean"),
            default=(tot_bwd_len / max(tot_bwd_pkts, 1.0)), min_val=0.0, max_val=65535.0
        )
        flow_bytes_s = sf(
            raw.get("Flow Bytes/s"),
            default=((tot_fwd_len + tot_bwd_len) / (max(flow_duration, 1.0) / 1e6)), min_val=0.0, max_val=1_000_000_000.0
        )
        flow_pkts_s = sf(
            raw.get("Flow Packets/s"),
            default=((tot_fwd_pkts + tot_bwd_pkts) / (max(flow_duration, 1.0) / 1e6)), min_val=0.0, max_val=10_000_000.0
        )
        flow_iat_mean = sf(
            raw.get("Flow IAT Mean"),
            default=(flow_duration / max(tot_fwd_pkts + tot_bwd_pkts, 1.0)), min_val=0.0, max_val=120_000_000.0
        )
        flow_iat_std = sf(
            raw.get("Flow IAT Std"),
            default=50.0, min_val=0.0, max_val=120_000_000.0
        )
        fwd_hdr_len = sf(
            raw.get("Fwd Header Length"),
            default=(tot_fwd_pkts * 20.0), min_val=0.0, max_val=10_000_000.0
        )
        bwd_hdr_len = sf(
            raw.get("Bwd Header Length"),
            default=(tot_bwd_pkts * 20.0), min_val=0.0, max_val=10_000_000.0
        )
        pkt_len_mean = sf(
            raw.get("Packet Length Mean"),
            default=((tot_fwd_len + tot_bwd_len) / max(tot_fwd_pkts + tot_bwd_pkts, 1.0)), min_val=0.0, max_val=65535.0
        )
        pkt_len_std = sf(
            raw.get("Packet Length Std"),
            default=25.0, min_val=0.0, max_val=65535.0
        )
        syn_default = 1.0 if event.get("event_type") in ["port_scan", "failed_login", "brute_force"] else 0.0
        syn_count = sf(
            raw.get("SYN Flag Count"),
            default=syn_default, min_val=0.0, max_val=1.0
        )
        ack_count = sf(
            raw.get("ACK Flag Count"),
            default=1.0, min_val=0.0, max_val=1.0
        )
        avg_pkt_size = sf(
            raw.get("Average Packet Size"),
            default=pkt_len_mean, min_val=0.0, max_val=65535.0
        )
        init_win_fwd = sf(
            raw.get("Init_Win_bytes_forward"),
            default=29200.0, min_val=-1.0, max_val=65535.0
        )

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
