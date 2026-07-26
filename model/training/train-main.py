import pandas as pd
import numpy as np
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
from collections import defaultdict
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pipeline import (
    log,
    save_model_artefacts,
    generate_fingerprints,
    feature_importance,
    feature_cutoffs,
    fingerprint_database,
    hash_consistency,
)


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
fingerprint_df = generate_fingerprints(model, X, le, top_n=3)
df_result = pd.concat([df, fingerprint_df], axis=1)
print(df_result[['label2', 'predicted_label', 'confidence', 'top_classes', 'fingerprint_hash']].head())


# 5. Extract feature importance
log("Global importance of all features across model")
features = feature_importance(model, top_n=20)
 
log("Feature contribution percentages across all trees and predictions")
importance_df = feature_cutoffs(features)


# 6. Create fingerprint reference database
log("Building fingerprint reference database from test set...")
y_test_labels = le.inverse_transform(y_test)
reference_db  = fingerprint_database(model, X_test, y_test_labels, le)
 
print("\nFingerprints per attack type:")
for label, entries in reference_db.items():
    print(f"  {label}: {len(entries)} fingerprints")

# 7. Check that the same traffic signature from the same device will always produce the same hash
log("Checking hash consistency across two runs...")
hash_consistency(model, X_test)

# 8. Save model artifects
save_model_artefacts(model, le, X.columns.tolist())