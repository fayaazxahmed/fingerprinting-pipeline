import pandas as pd
import numpy as np
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
import hashlib
import json

df = pd.read_csv("Datasets/CICIOT23/train/train.csv")
df.dropna(inplace=True)
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# 1. Prepare Data
feature_cols = [
    'flow_duration', 'Header_Length', 'Protocol Type', 'Duration', 'Rate',
    'Srate', 'Drate', 'fin_flag_number', 'syn_flag_number', 'rst_flag_number',
    'psh_flag_number', 'ack_flag_number', 'ece_flag_number', 'cwr_flag_number',
    'ack_count', 'syn_count', 'fin_count', 'urg_count', 'rst_count',
    'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP', 'UDP',
    'DHCP', 'ARP', 'ICMP', 'IPv', 'LLC', 'Tot sum', 'Min', 'Max', 'AVG',
    'Std', 'Tot size', 'IAT', 'Number', 'Magnitue', 'Radius', 'Covariance',
    'Variance', 'Weight'
]

X = df[feature_cols]
y = df['label']

# Encode string labels → integers (required by XGBoost)
le = LabelEncoder()
y_encoded = le.fit_transform(y)
num_classes = len(le.classes_)
print(f"Classes ({num_classes}): {le.classes_}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)

# 2. Train XGBoost
model = XGBClassifier(
    objective='multi:softprob',
    num_class=num_classes,
    n_estimators=300,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    use_label_encoder=False,
    eval_metric='mlogloss',
    early_stopping_rounds=20,
    random_state=42,
    n_jobs=-1
)

model.fit(
    X_train, y_train,
    eval_set=[(X_test, y_test)],
    verbose=50
)

# 3. Evaluate
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred, target_names=le.classes_))

# 4. Generate Fingerprints
def generate_fingerprints(model, X, label_encoder, top_n=3):
    """
    Returns a DataFrame with one fingerprint row per input row containing:
      - predicted_label   : human-readable class name
      - confidence        : probability of the predicted class
      - top_n_classes     : top N likely classes with probabilities
      - prob_vector       : full probability distribution (all classes)
      - fingerprint_hash  : SHA-256 hash of the probability vector (unique ID)
    """
    proba = model.predict_proba(X)                        # shape: (n_rows, n_classes)
    pred_idx = np.argmax(proba, axis=1)
    pred_labels = label_encoder.inverse_transform(pred_idx)

    fingerprints = []
    for i, (probs, label) in enumerate(zip(proba, pred_labels)):

        # Top N classes by probability
        top_idx = np.argsort(probs)[::-1][:top_n]
        top_classes = {
            label_encoder.classes_[j]: round(float(probs[j]), 6)
            for j in top_idx
        }

        # Stable hash of the full probability vector
        prob_bytes = probs.astype(np.float32).tobytes()
        fp_hash = hashlib.sha256(prob_bytes).hexdigest()

        fingerprints.append({
            'predicted_label': label,
            'confidence': round(float(probs[pred_idx[i]]), 6),
            'top_classes': top_classes,          # dict  → inspect or serialize
            'prob_vector': probs.tolist(),        # full distribution
            'fingerprint_hash': fp_hash              # unique row identity
        })

    return pd.DataFrame(fingerprints, index=X.index)

# Run on full dataframe
fingerprint_df = generate_fingerprints(model, X, le, top_n=3)

# Attach back to original data
df_result = pd.concat([df, fingerprint_df], axis=1)

print(df_result[['label', 'predicted_label', 'confidence', 'top_classes', 'fingerprint_hash']].head())