import os
import time
import hashlib
import logging
import joblib
import numpy as np
import pandas as pd
from collections import defaultdict
from xgboost import XGBClassifier

_ROOT = os.path.dirname(os.path.abspath(__file__))

CSV_PATH = os.environ.get("CSV_PATH", os.path.join(_ROOT, "captures", "features.csv"))
_MODEL_DIR = os.environ.get("MODEL_DIR", os.path.join(_ROOT, "model", "saved"))
MODEL_PATH = os.path.join(_MODEL_DIR, "xgb_classifier.ubj")
ENCODER_PATH = os.path.join(_MODEL_DIR, "label_encoder.pkl")
FEATURES_PATH = os.path.join(_MODEL_DIR, "feature_columns.pkl")
 
DEVICE_COL = "src_ip"          # Column in extractor CSV that identifies devices
POLL_INTERVAL = 1.0               # Seconds between file change checks
FLUSH_TIMEOUT = 60.0              # Seconds to wait before giving up on a flush
FLUSHES_PER_DEVICE = 20                # Optimal number of flushes to collect per device
TOP_N_CLASSES = 3                 # Top N classes shown per fingerprint
OUTPUT_PATH = "fingerprint_results.csv"

# Columns to exclude from feature matrix, matching training-time drop_cols
DROP_COLS = [
    'label_full', 'label1', 'label2', 'label3', 'label4',
    'device_name', 'device_mac', 'timestamp', 'timestamp_start',
    'timestamp_end', 'log_data-types', 'network_ips_all',
    'network_ips_dst', 'network_ips_src', 'network_macs_all',
    'network_macs_dst', 'network_macs_src', 'network_ports_all',
    'network_ports_dst', 'network_ports_src', 'network_protocols_all',
    'network_protocols_dst', 'network_protocols_src',
    'window_start', 'src_ip',
]

from log_util import log

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S"
)
_logger = logging.getLogger(__name__)

# Model artifacts
def load_model_artefacts(model_path=MODEL_PATH, encoder_path=ENCODER_PATH, features_path=FEATURES_PATH):
    log("Loading model artefacts...")
 
    missing = [p for p in [model_path, encoder_path, features_path]
               if not os.path.exists(p)]
    if missing:
        raise FileNotFoundError(
            f"Model file(s) not found: {missing}\n"
            "Ensure xgb_classifier.ubj, label_encoder.pkl, "
            "and feature_columns.pkl are present."
        )
 
    model = XGBClassifier()
    model.load_model(model_path)
 
    le              = joblib.load(encoder_path)
    feature_columns = joblib.load(features_path)
 
    log(f"Model loaded — {len(le.classes_)} classes, "
        f"{len(feature_columns)} features")
    return model, le, feature_columns

def save_model_artefacts(model, le, feature_columns, model_path=MODEL_PATH, encoder_path=ENCODER_PATH, features_path=FEATURES_PATH):
    model.save_model(model_path)
    joblib.dump(le, encoder_path)
    joblib.dump(feature_columns, features_path)
    log(f"Model artefacts saved: {model_path}, {encoder_path}, {features_path}")

# Fingerprint Generation
def generate_fingerprints(model, X, label_encoder, top_n=TOP_N_CLASSES):
    proba       = model.predict_proba(X)
    pred_idx    = np.argmax(proba, axis=1)
    pred_labels = label_encoder.inverse_transform(pred_idx)
 
    fingerprints = []
    for i, (probs, label) in enumerate(zip(proba, pred_labels)):
        top_idx     = np.argsort(probs)[::-1][:top_n]
        top_classes = {
            label_encoder.classes_[j]: round(float(probs[j]), 6)
            for j in top_idx
        }
 
        prob_bytes = probs.astype(np.float32).tobytes()
        fp_hash    = hashlib.sha256(prob_bytes).hexdigest()
 
        fingerprints.append({
            'predicted_label':  label,
            'confidence':       round(float(probs[pred_idx[i]]), 6),
            'top_classes':      top_classes,
            'prob_vector':      probs.tolist(),
            'is_attack':        label.lower() != 'benign',
            'fingerprint_hash': fp_hash
        })
 
    return pd.DataFrame(fingerprints, index=X.index)

# Feature Importance
def feature_importance(model, top_n=20):
    importance_dict = model.get_booster().get_score(importance_type='gain')
 
    importance_df = pd.DataFrame([
        {'feature': k, 'importance': v}
        for k, v in importance_dict.items()
    ]).sort_values('importance', ascending=False)
 
    importance_df['importance_pct'] = (
        importance_df['importance'] / importance_df['importance'].sum() * 100
    ).round(2)
 
    print(f"\nTop {top_n} Most Important Features Globally:")
    print(importance_df.head(top_n).to_string(index=False))
 
    return importance_df
 
def feature_cutoffs(importance_df, targets=(0.50, 0.70, 0.80, 0.90)):
    importance_df = importance_df.sort_values(
        'importance', ascending=False
    ).copy()
    importance_df['cumulative_pct'] = importance_df['importance_pct'].cumsum()
 
    print("\nCumulative Feature Importance:")
    print(f"{'Features':>10} {'Cumulative %':>15}")
    print("-" * 30)
 
    for i, row in importance_df.iterrows():
        n_features = importance_df.index.get_loc(i) + 1
        print(f"{n_features:>10} {row['cumulative_pct']:>14.2f}%")
 
    print("\nFeatures needed to reach thresholds:")
    for target in targets:
        n = (importance_df['cumulative_pct'] <= target * 100).sum() + 1
        print(f"  {int(target * 100)}% importance: {n} features")
 
    return importance_df

# Reference fingerprint database
def fingerprint_database(model, X, y_true_labels, le):
    proba       = model.predict_proba(X)
    pred_idx    = np.argmax(proba, axis=1)
    pred_labels = le.inverse_transform(pred_idx)
 
    reference_db = defaultdict(list)
 
    for i, probs in enumerate(proba):
        prob_bytes = probs.astype(np.float32).tobytes()
        fp_hash    = hashlib.sha256(prob_bytes).hexdigest()
 
        reference_db[y_true_labels[i]].append({
            'fingerprint_hash': fp_hash,
            'prob_vector':      probs.tolist(),
            'predicted_label':  pred_labels[i],
            'confidence':       round(float(probs[pred_idx[i]]), 6)
        })
 
    return dict(reference_db)

# Check consistency of generated fingerprint hashes
def hash_consistency(model, X, n_samples=100):
    sample = X.sample(n=n_samples, random_state=42)
 
    def get_hashes():
        hashes = []
        for _, row in sample.iterrows():
            proba      = model.predict_proba(pd.DataFrame([row]))[0]
            prob_bytes = proba.astype(np.float32).tobytes()
            hashes.append(hashlib.sha256(prob_bytes).hexdigest())
        return hashes
 
    hashes_run1 = get_hashes()
    hashes_run2 = get_hashes()
 
    matches = sum(h1 == h2 for h1, h2 in zip(hashes_run1, hashes_run2))
    print(f"\nHash consistency: {matches}/{n_samples} identical across two runs")
    return matches == n_samples

# Detect newly flushed captures
def get_file_state(path):
    stat = os.stat(path)
    return stat.st_mtime, stat.st_size
 
def wait_for_flush(path, last_state, timeout=FLUSH_TIMEOUT, poll=POLL_INTERVAL):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            current_state = get_file_state(path)
        except FileNotFoundError:
            log(f"CSV not found at {path}, retrying...")
            time.sleep(poll)
            continue
 
        if current_state != last_state:
            log(f"Flush detected — size: {current_state[1]:,} bytes")
            return True, current_state
 
        time.sleep(poll)
 
    log("Flush timeout reached — no new data written.")
    return False, last_state

# Detect new devices
def discover_devices(path=CSV_PATH, flush_timeout=FLUSH_TIMEOUT, poll=POLL_INTERVAL):
    log(f"Waiting for first flush from {path} ...")
 
    deadline = time.time() + flush_timeout
    while not os.path.exists(path):
        if time.time() > deadline:
            raise TimeoutError(f"CSV file never appeared at {path}")
        time.sleep(poll)
 
    initial_state = get_file_state(path)
    flushed, new_state = wait_for_flush(
        path, initial_state, timeout=flush_timeout
    )
 
    if not flushed:
        raise TimeoutError("No flush detected during device discovery.")
 
    df      = pd.read_csv(path)
    devices = df[DEVICE_COL].dropna().unique().tolist()
 
    log(f"Discovered {len(devices)} device(s): {devices}")
    return devices, df, new_state

# Traffic Detection
def collect_traffic(path, current_state, n_devices, flushes_per_device=FLUSHES_PER_DEVICE):
    target_flushes = flushes_per_device * n_devices
    log(f"Collecting {target_flushes} flushes "
        f"({flushes_per_device} per device × {n_devices} devices)...")
 
    frames         = []
    flush_count    = 0
    last_row_count = 0
 
    while flush_count < target_flushes:
        flushed, current_state = wait_for_flush(path, current_state)
 
        if not flushed:
            log(f"Collection stopped early after {flush_count} flushes.")
            break
 
        df_current     = pd.read_csv(path)
        new_rows       = df_current.iloc[last_row_count:]
        last_row_count = len(df_current)
 
        if len(new_rows) == 0:
            log("Flush detected but no new rows — skipping.")
            continue
 
        frames.append(new_rows)
        flush_count += 1
 
        device_counts = (
            new_rows[DEVICE_COL].value_counts().to_dict()
            if DEVICE_COL in new_rows.columns else {}
        )
        log(f"Flush {flush_count}/{target_flushes} — "
            f"{len(new_rows)} new rows | {device_counts}")
 
    if not frames:
        raise RuntimeError("No data collected across any flushes.")
 
    combined = pd.concat(frames, ignore_index=True)
    log(f"Collection complete — {len(combined):,} total rows "
        f"across {flush_count} flushes")
    return combined

# Prepare and summarize output data
def prepare_features(df, feature_columns, drop_cols=None):
    if drop_cols is None:
        drop_cols = DROP_COLS
 
    meta_cols = [c for c in [DEVICE_COL, 'window_start'] if c in df.columns]
    df_meta   = df[meta_cols].copy() if meta_cols else pd.DataFrame(index=df.index)
 
    cols_to_drop = [c for c in drop_cols if c in df.columns]
    df_features  = df.drop(columns=cols_to_drop, errors='ignore')
    df_features  = df_features.reindex(columns=feature_columns, fill_value=0)
 
    missing = [c for c in feature_columns if c not in df.columns]
    if missing:
        log(f"WARNING: {len(missing)} feature(s) missing, filled with 0: {missing}")
 
    return df_features, df_meta

def summarize_by_device(df_meta, fingerprint_df):
    combined = pd.concat(
        [df_meta.reset_index(drop=True),
         fingerprint_df.reset_index(drop=True)],
        axis=1
    )
 
    if DEVICE_COL not in combined.columns:
        log("No device column in output — skipping per-device summary.")
        return combined, pd.DataFrame()
 
    summaries = []
    for device, group in combined.groupby(DEVICE_COL):
        dominant_label = group['predicted_label'].mode()[0]
        consistency    = (group['predicted_label'] == dominant_label).mean()
 
        summaries.append({
            'device':          device,
            'total_rows':      len(group),
            'attack_rows':     int(group['is_attack'].sum()),
            'benign_rows':     int((~group['is_attack']).sum()),
            'dominant_label':  dominant_label,
            'consistency':     round(consistency, 4),
            'mean_confidence': round(group['confidence'].mean(), 4),
            'unique_hashes':   group['fingerprint_hash'].nunique()
        })
 
    summary_df = pd.DataFrame(summaries)
 
    log("\n── Per-Device Summary " + "─" * 40)
    for _, row in summary_df.iterrows():
        flag = "ATTACK DETECTED" if row['attack_rows'] > 0 else "Benign"
        log(
            f"  {str(row['device']):<20} | {flag:<18} | "
            f"Consistency: {row['consistency']:.0%} | "
            f"Confidence: {row['mean_confidence']:.4f} | "
            f"Unique hashes: {row['unique_hashes']}"
        )
    log("─" * 62 + "\n")
 
    return combined, summary_df
