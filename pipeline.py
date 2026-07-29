import os
import time
import hashlib
import logging
import joblib
import docker
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
FLUSHES_PER_DEVICE = 1                # Optimal number of flushes to collect per device
TOP_N_CLASSES = 3                 # Top N classes shown per fingerprint
OUTPUT_PATH = "fingerprint_results.csv"
AGGREGATE_ATTACK_THRESHOLD = 0.50
HOSTILE_WINDOW_THRESHOLD = 0.50

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
    pred_labels = apply_aggregate_threshold(proba, pred_labels, label_encoder)
 
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

def apply_aggregate_threshold(proba, pred_labels, le):
    class_list  = list(le.classes_)

    if 'benign' not in class_list:
        log("WARNING: 'benign' class not found in label encoder — "
            "aggregate threshold cannot be applied.")
        return pred_labels

    benign_idx   = class_list.index('benign')
    overrides    = 0
    pred_labels  = pred_labels.copy()

    for i in range(len(pred_labels)):
        if pred_labels[i].lower() != 'benign':
            continue  # already classified as attack, no override needed

        benign_prob  = proba[i][benign_idx]
        attack_prob  = 1.0 - benign_prob   # combined probability of all non-benign classes

        if attack_prob >= AGGREGATE_ATTACK_THRESHOLD:
            # Reclassify as the highest-scoring individual attack class
            attack_proba         = proba[i].copy()
            attack_proba[benign_idx] = 0
            top_attack_idx       = np.argmax(attack_proba)
            prev_label           = pred_labels[i]
            pred_labels[i]       = le.classes_[top_attack_idx]
            overrides           += 1

            log(f"  Aggregate override row {i}: {prev_label} → "
                f"{pred_labels[i]} "
                f"(benign: {benign_prob:.1%}, "
                f"combined attack: {attack_prob:.1%})")

    if overrides:
        log(f"Aggregate threshold ({AGGREGATE_ATTACK_THRESHOLD:.0%}) "
            f"triggered {overrides} override(s).")

    return pred_labels

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

# Map IP address to docker container name
def get_container_name_map():
    """
    Queries the Docker API and returns a dict mapping each
    container's IP address to its name.
    
    Returns:
        dict: { '192.168.10.21': 'my_container_name', ... }
    """
    try:
        client     = docker.from_env()
        containers = client.containers.list()
        ip_to_name = {}

        for container in containers:
            networks = container.attrs['NetworkSettings']['Networks']
            for network in networks.values():
                ip = network.get('IPAddress')
                if ip:
                    # Strip leading slash from container name
                    name = container.name.lstrip('/')
                    ip_to_name[ip] = name

        log(f"Docker API resolved {len(ip_to_name)} container IP mappings")
        return ip_to_name

    except Exception as e:
        log(f"WARNING: Could not query Docker API — {e}")
        log("Container names will not be included in summary.")
        return {}

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

    # Resolve container names from Docker API
    ip_to_name = get_container_name_map()

    summaries = []
    for device, group in combined.groupby(DEVICE_COL):
        dominant_label = group['predicted_label'].mode()[0]
        consistency    = (group['predicted_label'] == dominant_label).mean()
        attack_ratio = int(group['is_attack'].sum()) / len(group) if len(group) > 0 else 0
        is_attack    = attack_ratio >= HOSTILE_WINDOW_THRESHOLD

        # Look up container name, fall back to IP if not found
        container_name = ip_to_name.get(device, 'unknown')

        summaries.append({
            'device':           device,
            'container_name':   container_name,
            'total_rows':       len(group),
            'attack_rows':      int(group['is_attack'].sum()),
            'benign_rows':      int((~group['is_attack']).sum()),
            'attack_ratio':    round(attack_ratio, 4),
            'is_hostile':      is_attack,
            'dominant_label':   dominant_label,
            'consistency':      round(consistency, 4),
            'mean_confidence':  round(group['confidence'].mean(), 4),
            'unique_hashes':    group['fingerprint_hash'].nunique()
        })

    summary_df = pd.DataFrame(summaries)

    log("\n── Per-Device Summary " + "─" * 40)
    for _, row in summary_df.iterrows():
        attack_ratio = row['attack_rows'] / row['total_rows'] if row['total_rows'] > 0 else 0
        flag = "ATTACK DETECTED" if attack_ratio >= HOSTILE_WINDOW_THRESHOLD else "Benign"
        log(
            f"  {str(row['container_name']):<25} ({str(row['device']):<15}) | "
            f"{flag:<18} | "
            f"Attack ratio: {attack_ratio:.0%} | "
            f"Consistency: {row['consistency']:.0%} | "
            f"Confidence: {row['mean_confidence']:.4f} | "
            f"Unique hashes: {row['unique_hashes']}"
        )
    log("─" * 62 + "\n")

    return combined, summary_df

def plot_device_fingerprints(model, X, df_meta, fingerprint_df, top_n_features=15, output_path="device_fingerprints.png"):
    import matplotlib
    matplotlib.use("Agg")  # non-interactive backend for server environments
    import matplotlib.pyplot as plt
    import matplotlib.gridspec as gridspec
    import seaborn as sns
    import numpy as np
 
    # ── Palette and style ─────────────────────────────────────────────────────
    plt.rcParams.update({
        "figure.facecolor":  "#ffffff",
        "axes.facecolor":    "#ffffff",
        "axes.edgecolor":    "#444444",
        "axes.labelcolor":   "#000000",
        "axes.titlecolor":   "#000000",
        "xtick.color":       "#000000",
        "ytick.color":       "#000000",
        "text.color":        "#000000",
        "grid.color":        "#d0d0d0",
        "grid.linestyle":    "--",
        "grid.alpha":        0.5,
        "font.family":       "monospace",
    })
 
    ACCENT_BENIGN  = "#3fb950"   # green  — benign traffic
    ACCENT_ATTACK  = "#f85149"   # red    — attack traffic
    ACCENT_NEUTRAL = "#58a6ff"   # blue   — feature bars
    ACCENT_WARN    = "#d29922"   # amber  — low confidence
 
    # ── Get global feature importance for reference ranking ───────────────────
    importance_dict  = model.get_booster().get_score(importance_type='gain')
    feature_names    = X.columns.tolist()
 
    # Rank features by global importance so bars are ordered meaningfully
    ranked_features = sorted(
        [f for f in feature_names if f in importance_dict],
        key=lambda f: importance_dict.get(f, 0),
        reverse=True
    )[:top_n_features]
 
    # ── Combine meta and fingerprint data ─────────────────────────────────────
    combined = pd.concat(
        [df_meta.reset_index(drop=True),
         fingerprint_df.reset_index(drop=True),
         X.reset_index(drop=True)],
        axis=1
    )
 
    devices     = combined[DEVICE_COL].dropna().unique().tolist()
    n_devices   = len(devices)
 
    if n_devices == 0:
        log("No devices found for plotting.")
        return
 
    # ── Layout — one row per device, three panels per row ────────────────────
    # Panel 1: feature value bar chart
    # Panel 2: class probability distribution
    # Panel 3: confidence + consistency gauges
    fig = plt.figure(figsize=(22, 6 * n_devices), facecolor="#e0e9f8")
    fig.suptitle(
        "Device Network Fingerprint Analysis",
        fontsize=16, fontweight="bold", color="#000000",
        y=1.01 if n_devices > 1 else 1.04
    )
 
    outer = gridspec.GridSpec(
        n_devices, 1, figure=fig,
        hspace=0.55
    )
 
    for dev_idx, device in enumerate(devices):
        dev_rows   = combined[combined[DEVICE_COL] == device]
        dev_X      = dev_rows[ranked_features].mean()  # mean feature values across all rows
 
        # Fingerprint stats for this device
        dominant_label  = dev_rows['predicted_label'].mode()[0]
        consistency     = (dev_rows['predicted_label'] == dominant_label).mean()
        mean_confidence = dev_rows['confidence'].mean()
        HOSTILE_WINDOW_THRESHOLD = 0.30
        attack_ratio = dev_rows['is_attack'].sum() / len(dev_rows)
        is_attack    = attack_ratio >= HOSTILE_WINDOW_THRESHOLD
        n_rows          = len(dev_rows)
        unique_hashes   = dev_rows['fingerprint_hash'].nunique()
 
        # Mean probability vector across all rows for this device
        prob_vectors    = np.array(dev_rows['prob_vector'].tolist())
        mean_probs      = prob_vectors.mean(axis=0)
 
        # Container name if available
        container_name  = dev_rows['container_name'].iloc[0] \
            if 'container_name' in dev_rows.columns else device
 
        # Colour for this device based on attack status
        device_colour   = ACCENT_ATTACK if is_attack else ACCENT_BENIGN
 
        # ── Inner grid: 3 panels ──────────────────────────────────────────────
        inner = gridspec.GridSpecFromSubplotSpec(
            1, 3, subplot_spec=outer[dev_idx],
            width_ratios=[2.5, 2, 1],
            wspace=0.35
        )
 
        # ── Device header label ───────────────────────────────────────────────
        header = f"{'⚠ ' if is_attack else '✓ '}{container_name}  ({device})"
        fig.add_subplot(outer[dev_idx]).set_visible(False)
        ax_header = fig.add_axes(
            [outer[dev_idx].get_position(fig).x0,
             outer[dev_idx].get_position(fig).y1,
             outer[dev_idx].get_position(fig).width, 0.0]
        )
        ax_header.set_visible(False)
 
        # Panel title drawn on Panel 1 as a row header
        ax1 = fig.add_subplot(inner[0])
        ax1.set_title(
            f"{'⚠  ' if is_attack else '✓  '}{container_name}   "
            f"({device})   ·   {n_rows} windows   ·   "
            f"{unique_hashes} unique fingerprints",
            loc="left", fontsize=10, fontweight="bold",
            color=device_colour, pad=10
        )
 
        # ── Panel 1: Feature values (mean across windows) ─────────────────────
        feature_vals  = [dev_X.get(f, 0) for f in ranked_features]
        feature_labels = [f.replace("network_", "").replace("log_", "log/")
                          for f in ranked_features]
 
        # Normalise bar lengths to [0, 1] for visual comparability
        max_val       = max(feature_vals) if max(feature_vals) > 0 else 1
        norm_vals     = [v / max_val for v in feature_vals]
 
        # Colour bars by global importance rank — brighter = more important
        bar_alphas    = [1.0 - (i / top_n_features) * 0.55
                         for i in range(len(ranked_features))]
        bar_colours   = [(*matplotlib.colors.to_rgb(ACCENT_NEUTRAL), a)
                         for a in bar_alphas]
 
        bars = ax1.barh(
            range(len(ranked_features)),
            norm_vals,
            color=bar_colours,
            height=0.65,
            edgecolor="none"
        )
 
        # Annotate bars with actual values
        for bar, val in zip(bars, feature_vals):
            ax1.text(
                bar.get_width() + 0.01, bar.get_y() + bar.get_height() / 2,
                f"{val:.2f}", va="center", ha="left",
                fontsize=7, color="black"
            )
 
        ax1.set_yticks(range(len(ranked_features)))
        ax1.set_yticklabels(feature_labels, fontsize=8)
        ax1.set_xlabel("Normalised value  (raw value annotated)", fontsize=8)
        ax1.set_xlim(0, 1.25)
        ax1.invert_yaxis()
        ax1.grid(axis="x")
        ax1.set_ylabel("Feature  (top by global importance)", fontsize=8)
 
        # Importance rank markers on y axis
        for i, feat in enumerate(ranked_features):
            rank = list(importance_dict.keys()).index(feat) + 1 \
                if feat in importance_dict else "—"
            ax1.text(
                -0.02, i, f"#{rank}",
                va="center", ha="right",
                fontsize=7, color="#555555",
                transform=ax1.get_yaxis_transform()
            )
 
        # ── Panel 2: Class probability distribution ───────────────────────────
        ax2 = fig.add_subplot(inner[1])
 
        # Only show classes with meaningful probability (> 1%)
        class_names  = list(fingerprint_df.attrs.get(
            'class_names', [f"class_{i}" for i in range(len(mean_probs))]
        ))
 
        # Get class names from the top_classes field if available
        sample_top   = dev_rows['top_classes'].iloc[0]
        if isinstance(sample_top, dict):
            all_classes  = list(sample_top.keys())
        else:
            import ast
            all_classes  = list(ast.literal_eval(sample_top).keys())
 
        # Aggregate mean probability per class across all rows for this device
        top_class_probs = {}
        for _, row in dev_rows.iterrows():
            tc = row['top_classes'] if isinstance(row['top_classes'], dict) \
                else ast.literal_eval(row['top_classes'])
            for cls, prob in tc.items():
                top_class_probs[cls] = top_class_probs.get(cls, 0) + prob
 
        total_weight = sum(top_class_probs.values())
        top_class_probs = {
            k: v / total_weight
            for k, v in sorted(
                top_class_probs.items(), key=lambda x: x[1], reverse=True
            )
        }
 
        cls_labels = list(top_class_probs.keys())
        cls_vals   = list(top_class_probs.values())
 
        cls_colours = []
        for cls in cls_labels:
            if cls.lower() == "benign":
                cls_colours.append(ACCENT_BENIGN)
            else:
                cls_colours.append(ACCENT_ATTACK)
 
        ax2.barh(
            range(len(cls_labels)),
            cls_vals,
            color=cls_colours,
            height=0.6,
            edgecolor="none",
            alpha=0.85
        )
 
        for i, val in enumerate(cls_vals):
            ax2.text(
                val + 0.005, i,
                f"{val:.1%}", va="center", ha="left",
                fontsize=8, color="black"
            )
 
        ax2.set_yticks(range(len(cls_labels)))
        ax2.set_yticklabels(cls_labels, fontsize=8)
        ax2.set_xlabel("Mean probability across windows", fontsize=8)
        ax2.set_xlim(0, 1.2)
        ax2.invert_yaxis()
        ax2.grid(axis="x")
        ax2.set_title("Class probability distribution", fontsize=9,
                       color="#555555", pad=6)
 
        # ── Panel 3: Confidence and consistency gauges ────────────────────────
        ax3 = fig.add_subplot(inner[2])
        ax3.set_xlim(0, 1)
        ax3.set_ylim(0, 1)
        ax3.axis("off")
 
        def draw_gauge(ax, x, y, value, label, colour, width=0.35, height=0.06):
            """Draws a simple horizontal gauge bar with label and value."""
            # Background track
            ax.add_patch(plt.Rectangle(
                (x, y), width, height,
                facecolor="#eeeeee", edgecolor="#bbbbbb",
                linewidth=0.8, transform=ax.transAxes, clip_on=False
            ))
            # Fill
            ax.add_patch(plt.Rectangle(
                (x, y), width * value, height,
                facecolor=colour, edgecolor="none", alpha=0.9,
                transform=ax.transAxes, clip_on=False
            ))
            ax.text(x, y + height + 0.025, label,
                    transform=ax.transAxes, fontsize=8,
                    color="#555555", va="bottom")
            ax.text(x + width + 0.02, y + height / 2, f"{value:.1%}",
                    transform=ax.transAxes, fontsize=9,
                    color="#000000", va="center", fontweight="bold")
 
        conf_colour = (ACCENT_BENIGN if mean_confidence > 0.80
                       else ACCENT_WARN if mean_confidence > 0.60
                       else ACCENT_ATTACK)
        cons_colour = (ACCENT_BENIGN if consistency > 0.80
                       else ACCENT_WARN if consistency > 0.60
                       else ACCENT_ATTACK)
 
        draw_gauge(ax3, 0.05, 0.78, mean_confidence,
                   "Mean confidence", conf_colour)
        draw_gauge(ax3, 0.05, 0.58, consistency,
                   "Label consistency", cons_colour)
 
        # Attack/benign verdict badge
        verdict_colour = ACCENT_ATTACK if is_attack else ACCENT_BENIGN
        verdict_text   = "ATTACK DETECTED" if is_attack else "BENIGN"
        ax3.add_patch(plt.Rectangle(
            (0.05, 0.38), 0.88, 0.12,
            facecolor=verdict_colour, alpha=0.15,
            edgecolor=verdict_colour, linewidth=1.2,
            transform=ax3.transAxes, clip_on=False
        ))
        ax3.text(0.49, 0.44, verdict_text,
                 transform=ax3.transAxes, fontsize=10,
                 color=verdict_colour, fontweight="bold",
                 ha="center", va="center")
 
        # Summary stats block
        stats = [
            ("Windows collected",  str(n_rows)),
            ("Unique fingerprints", str(unique_hashes)),
            ("Dominant class",     dominant_label),
            ("Attack windows",
             str(int(dev_rows['is_attack'].sum()))),
            ("Benign windows",
             str(int((~dev_rows['is_attack']).sum()))),
        ]
        y_pos = 0.28
        for stat_label, stat_val in stats:
            ax3.text(0.05, y_pos, stat_label + ":",
                     transform=ax3.transAxes, fontsize=7.5,
                     color="#555555", va="top")
            ax3.text(0.95, y_pos, stat_val,
                     transform=ax3.transAxes, fontsize=7.5,
                     color="#555555", va="top", ha="right",
                     fontweight="bold")
            y_pos -= 0.055
 
        ax3.set_title("Fingerprint summary", fontsize=9,
                       color="#555555", pad=6)
 
    plt.savefig(output_path, dpi=150, bbox_inches="tight",
                facecolor="#ffffff")
    plt.close()
    log(f"Device fingerprint plot saved to {output_path}")
