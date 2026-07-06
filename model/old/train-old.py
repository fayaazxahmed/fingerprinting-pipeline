import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report
from sklearn.feature_selection import SelectFromModel
from imblearn.over_sampling import SMOTE
import xgboost as xgb

# --- 1. Load Data ---
# For CIC IoT 2023: merge the CSV files
df = pd.read_csv("Datasets/CICIOT23/train/train.csv")

# --- 2. Preprocessing ---
df.dropna(inplace=True)
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# Encode device labels (fingerprint target)
le = LabelEncoder()
# For 2023: use 'label' column for attack type or device type
# For 2022 (post-IoTDevID extraction): use device MAC/name column
y = le.fit_transform(df['label'])
X = df.drop(columns=['label'])

# --- 3. Feature Selection via XGBoost importance ---
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

xgb_selector = xgb.XGBClassifier(n_estimators=100, use_label_encoder=False,
                                   eval_metric='mlogloss', n_jobs=-1)
xgb_selector.fit(X_scaled, y)
selector = SelectFromModel(xgb_selector, prefit=True, threshold="mean")
X_selected = selector.transform(X_scaled)
print(f"Selected {X_selected.shape[1]} features from {X_scaled.shape[1]}")

# --- 4. Handle Class Imbalance ---
smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X_selected, y)

# --- 5. Train/Test Split ---
X_train, X_test, y_train, y_test = train_test_split(
    X_resampled, y_resampled, test_size=0.2, random_state=42, stratify=y_resampled
)

# --- 6A. Random Forest (strong baseline) ---
rf = RandomForestClassifier(n_estimators=200, class_weight='balanced',
                             n_jobs=-1, random_state=42)
rf.fit(X_train, y_train)
y_pred_rf = rf.predict(X_test)
print("=== Random Forest ===")
print(classification_report(y_test, y_pred_rf, target_names=le.classes_))

# --- 6B. XGBoost ---
xgb_model = xgb.XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1,
                                use_label_encoder=False, eval_metric='mlogloss',
                                n_jobs=-1, random_state=42)
xgb_model.fit(X_train, y_train,
              eval_set=[(X_test, y_test)], verbose=False)
y_pred_xgb = xgb_model.predict(X_test)
print("=== XGBoost ===")
print(classification_report(y_test, y_pred_xgb, target_names=le.classes_))

# --- 7. Extract Device Fingerprints ---
# Feature importances as the fingerprint signature per device
importances = pd.DataFrame({
    'feature': X.columns[selector.get_support()],
    'importance': rf.feature_importances_
}).sort_values('importance', ascending=False)
print(importances.head(15))