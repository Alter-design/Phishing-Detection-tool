import pandas as pd
import numpy as np
import pickle
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import xgboost as xgb
import warnings
warnings.filterwarnings('ignore')

print("=" * 60)
print("PHISHING DETECTION MODEL TRAINING")
print("=" * 60)

# Load dataset
print("\n[1/5] Loading dataset...")
df = pd.read_csv("dataset/phishing_dataset.csv")

# Clean data - remove rows with NaN
df = df.dropna()
print(f"   Dataset loaded: {len(df)} samples")

# Prepare features and labels
feature_cols = [col for col in df.columns if col != 'Result']
X = df[feature_cols]
y = df['Result']

# Convert labels: -1 -> 0 (phishing), 1 -> 1 (legitimate)
y = y.map({-1: 0, 1: 1})

print(f"   Features: {len(feature_cols)}")
print(f"   Labels distribution: Phishing={sum(y==0)}, Legitimate={sum(y==1)}")

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"   Training set: {len(X_train)} samples")
print(f"   Test set: {len(X_test)} samples")

# Scale features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# ==================== RANDOM FOREST ====================
print("\n[2/5] Training Random Forest...")
rf_model = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)
rf_model.fit(X_train_scaled, y_train)

rf_pred = rf_model.predict(X_test_scaled)
rf_accuracy = accuracy_score(y_test, rf_pred)

print(f"   ✓ Random Forest Accuracy: {rf_accuracy:.4f} ({rf_accuracy*100:.2f}%)")

# ==================== XGBOOST ====================
print("\n[3/5] Training XGBoost...")
xgb_model = xgb.XGBClassifier(
    n_estimators=200,
    max_depth=10,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42,
    use_label_encoder=False,
    eval_metric='logloss'
)
xgb_model.fit(X_train_scaled, y_train)

xgb_pred = xgb_model.predict(X_test_scaled)
xgb_accuracy = accuracy_score(y_test, xgb_pred)

print(f"   ✓ XGBoost Accuracy: {xgb_accuracy:.4f} ({xgb_accuracy*100:.2f}%)")

# ==================== COMPARE MODELS ====================
print("\n[4/5] Model Comparison...")
print("=" * 50)
print(f"   Random Forest: {rf_accuracy*100:.2f}%")
print(f"   XGBoost:       {xgb_accuracy*100:.2f}%")
print("=" * 50)

# Choose best model
if xgb_accuracy >= rf_accuracy:
    best_model = xgb_model
    best_name = "XGBoost"
    best_accuracy = xgb_accuracy
else:
    best_model = rf_model
    best_name = "Random Forest"
    best_accuracy = rf_accuracy

print(f"\n   ★ Best Model: {best_name} ({best_accuracy*100:.2f}%)")

# Detailed classification report for best model
print(f"\n   Classification Report ({best_name}):")
if best_name == "XGBoost":
    print(classification_report(y_test, xgb_pred, target_names=['Phishing', 'Legitimate']))
else:
    print(classification_report(y_test, rf_pred, target_names=['Phishing', 'Legitimate']))

# Feature importance
print("\n   Top 10 Most Important Features:")
if best_name == "XGBoost":
    importance = xgb_model.feature_importances_
else:
    importance = rf_model.feature_importances_

feature_importance = sorted(zip(feature_cols, importance), key=lambda x: x[1], reverse=True)
for i, (feat, imp) in enumerate(feature_importance[:10]):
    print(f"   {i+1}. {feat}: {imp:.4f}")

# ==================== SAVE MODELS ====================
print("\n[5/5] Saving models...")

# Save both models
pickle.dump(rf_model, open("rf_model.pkl", "wb"))
pickle.dump(xgb_model, open("xgb_model.pkl", "wb"))
pickle.dump(scaler, open("scaler.pkl", "wb"))
pickle.dump(feature_cols, open("feature_cols.pkl", "wb"))

# Save best model as main model
pickle.dump(best_model, open("model.pkl", "wb"))

print(f"   ✓ rf_model.pkl saved")
print(f"   ✓ xgb_model.pkl saved")
print(f"   ✓ scaler.pkl saved")
print(f"   ✓ feature_cols.pkl saved")
print(f"   ✓ model.pkl saved (Best: {best_name})")

print("\n" + "=" * 60)
print(f"✅ TRAINING COMPLETE! Best Accuracy: {best_accuracy*100:.2f}%")
print("=" * 60)
