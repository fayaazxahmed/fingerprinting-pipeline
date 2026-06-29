import pandas as pd
import numpy as np
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
import hashlib
import joblib

# 1. Prepare Data
df_benign = pd.read_csv("Datasets/samples/attack_samples_10sec(in).csv")
df_benign.dropna(inplace=True)
df_benign.replace([np.inf, -np.inf], np.nan, inplace=True)
df_benign.dropna(inplace=True)

df_attacks = pd.read_csv("Datasets/samples/benign_samples_10sec(in).csv")
df_attacks.dropna(inplace=True)
df_attacks.replace([np.inf, -np.inf], np.nan, inplace=True)
df_attacks.dropna(inplace=True)

df = pd.concat([df_benign, df_attacks], axis=0, ignore_index=True)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)
drop_cols = [
    'label_full', 'label1', 'label2', 'label3', 'label4',
    'device_name', 'device_mac', 'timestamp', 'timestamp_start', 
    'timestamp_end', 'log_data-types', 'network_ips_all', 
    'network_ips_dst', 'network_ips_src', 'network_macs_all',
    'network_macs_dst', 'network_macs_src', 'network_ports_all',
    'network_ports_dst', 'network_ports_src', 'network_protocols_all',
    'network_protocols_dst', 'network_protocols_src'
]

X = df.drop(columns=drop_cols)
y = df['label2']

# Encode string labels to integers, required by XGBoost
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
    proba = model.predict_proba(X)
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
            'top_classes': top_classes,
            'prob_vector': probs.tolist(),
            'fingerprint_hash': fp_hash
        })

    return pd.DataFrame(fingerprints, index=X.index)

fingerprint_df = generate_fingerprints(model, X, le, top_n=3)
df_result = pd.concat([df, fingerprint_df], axis=1)
print(df_result.head(100))

model.save_model("xgb_classifier.ubj")
joblib.dump(le, "label_encoder.pkl")
joblib.dump(X.columns.tolist(), "feature_columns.pkl")