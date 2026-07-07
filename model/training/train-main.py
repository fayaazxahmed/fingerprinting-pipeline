import pandas as pd
import numpy as np
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
from collections import defaultdict
import hashlib
import joblib
import shap

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

# 5. Extract feature importance
def feature_importance(model, X, top_n=20):
    """
    Returns the top N most important features globally
    across all predictions, using XGBoost's built-in
    feature importance scores.
    """
    importance_dict = model.get_booster().get_score(importance_type='gain')
    
    importance_df = pd.DataFrame([
        {'feature': k, 'importance': v}
        for k, v in importance_dict.items()
    ]).sort_values('importance', ascending=False)
    
    # Normalize to percentage
    importance_df['importance_pct'] = (
        importance_df['importance'] / importance_df['importance'].sum() * 100
    ).round(2)
    
    print(f"Top {top_n} Most Important Features Globally:")
    print(importance_df.head(top_n).to_string(index=False))
    
    return importance_df

def feature_cutoffs(importance_df, targets=[0.50, 0.70, 0.80, 0.90]):
    """
    Shows how many features are needed to reach
    each cumulative importance threshold.
    """
    importance_df = importance_df.sort_values('importance', ascending=False).copy()
    importance_df['cumulative_pct'] = importance_df['importance_pct'].cumsum()
    
    print("Cumulative Feature Importance:")
    print(f"{'Features':>10} {'Cumulative %':>15}")
    print("-" * 30)
    
    for i, row in importance_df.iterrows():
        n_features = importance_df.index.get_loc(i) + 1
        print(f"{n_features:>10} {row['cumulative_pct']:>14.2f}%")
    
    return importance_df

# 6. Create fingerprint reference database
def fingerprint_database(model, X, y_true_labels, le):
    """
    Creates a reference database of known fingerprints
    grouped by their true class label.
    """
    proba = model.predict_proba(X)
    pred_idx = np.argmax(proba, axis=1)
    pred_labels = le.inverse_transform(pred_idx)
    
    reference_db = defaultdict(list)
    
    for i, probs in enumerate(proba):
        prob_bytes = probs.astype(np.float32).tobytes()
        fp_hash = hashlib.sha256(prob_bytes).hexdigest()
        
        reference_db[y_true_labels[i]].append({
            'fingerprint_hash': fp_hash,
            'prob_vector': probs.tolist(),
            'predicted_label': pred_labels[i],
            'confidence': round(float(probs[pred_idx[i]]), 6)
        })
    
    return dict(reference_db)

# 7. Check that the same traffic signature from the same device will always produce the same hash
def hash_consistency(model, X, n_samples=100):
    """
    Runs the same rows through the model twice and confirms
    the fingerprint hashes are identical both times.
    """
    sample = X.sample(n=n_samples, random_state=42)
    
    hashes_run1 = []
    hashes_run2 = []
    
    for _ , row in sample.iterrows():
        row_df = pd.DataFrame([row])
        
        proba = model.predict_proba(row_df)[0]
        prob_bytes = proba.astype(np.float32).tobytes()
        fp_hash = hashlib.sha256(prob_bytes).hexdigest()
        
        hashes_run1.append(fp_hash)
    
    # Run again
    for _, row in sample.iterrows():
        row_df = pd.DataFrame([row])
        
        proba = model.predict_proba(row_df)[0]
        prob_bytes = proba.astype(np.float32).tobytes()
        fp_hash = hashlib.sha256(prob_bytes).hexdigest()
        
        hashes_run2.append(fp_hash)
    
    matches = sum(h1 == h2 for h1, h2 in zip(hashes_run1, hashes_run2))
    print(f"Consistency: {matches}/{n_samples} hashes identical across two runs")
    return matches == n_samples

fingerprint_df = generate_fingerprints(model, X, le, top_n=3)
df_result = pd.concat([df, fingerprint_df], axis=1)

# Build fingerprint reference database using the test data
print("Fingerprints per attack types:")
y_test_labels = le.inverse_transform(y_test)
reference_db = fingerprint_database(model, X_test, y_test_labels, le)
for label, entries in reference_db.items():
    print(f"{label}: {len(entries)} fingerprints")

# Global feature importance across model
print("\nGlobal importance of all feature across model")
features = feature_importance(model, X_test, top_n=20)
print("\nFeatures contribution percentages across all trees and predictions")
importance_df = feature_cutoffs(features)

# Check hash consistency
print("\nHash consistency across two rounds of training:")
hash_consistency(model, X_test)

'''
model.save_model("xgb_classifier.ubj")
joblib.dump(le, "label_encoder.pkl")
joblib.dump(X.columns.tolist(), "feature_columns.pkl")
'''