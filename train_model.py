import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib
import os
import numpy as np

# Make sure this matches your downloaded file name exactly!
dataset_file = 'UNSW_NB15_training-set.csv'

if not os.path.exists(dataset_file):
    print(f"[!] Error: Could not find {dataset_file}. Please put it in the folder.")
    exit()

print("[*] Loading UNSW-NB15 dataset...")
df = pd.read_csv(dataset_file)

print("[*] Preprocessing data...")

# 1. Drop columns we don't need for binary detection
columns_to_drop = ['id', 'attack_cat']
for col in columns_to_drop:
    if col in df.columns:
        df.drop(col, axis=1, inplace=True)

# 2. Encode any text (object dtype) columns into numbers.
#    NOTE: earlier this listed fixed names ['proto','service','state'], but this
#    particular CSV already ships those as xProt/xServ/xState and pre-encoded as
#    integers. Detecting object dtype columns automatically makes this work
#    regardless of the exact column names/casing in whichever CSV is used.
categorical_columns = list(df.select_dtypes(include='object').columns)
label_encoders = {}
for col in categorical_columns:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
    label_encoders[col] = le

if categorical_columns:
    print(f"[*] Encoded text columns: {categorical_columns}")
else:
    print("[*] No text columns found - dataset is already numeric.")

# 3. Separate features (X) and target label (y)
X = df.drop('label', axis=1)
y = df['label']

print(f"[*] Original UNSW-NB15 features: {X.shape[1]}")
print(f"[*] Feature names: {list(X.columns)}")

# Split into 80% training data and 20% testing data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 4. Scale the data
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# 5. Train the AI Model
print("[*] Training Random Forest AI Model (This might take a minute or two)...")
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=1,
    max_depth=20,
    min_samples_split=5,
)
model.fit(X_train_scaled, y_train)

# 6. Evaluate the Model
print("[*] Evaluating Model Accuracy...")
predictions = model.predict(X_test_scaled)
accuracy = accuracy_score(y_test, predictions)
print(f"\n{'='*50}")
print(f"ACCURACY: {accuracy * 100:.2f}%")
print(f"{'='*50}\n")

print("Classification Report:")
print(classification_report(y_test, predictions, target_names=['Normal', 'Malicious']))

print("\nConfusion Matrix:")
cm = confusion_matrix(y_test, predictions)
print(cm)
if cm.shape == (2, 2):
    print(f"""
        Predicted
        Normal  Malicious
Actual Normal     {cm[0][0]}      {cm[0][1]}
       Malicious  {cm[1][0]}      {cm[1][1]}
""")
else:
    print("[!] Unexpected confusion matrix shape:", cm.shape)

# 7. Feature Importance Analysis
print("\n" + "="*50)
print("TOP 10 MOST IMPORTANT FEATURES:")
print("="*50)
feature_importance = pd.DataFrame({
    'feature': X.columns,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)
print(feature_importance.head(10))

# 8. Save the trained model
print("\n[*] Saving the trained brain to files...")
joblib.dump(model, 'ids_rf_model.pkl')
joblib.dump(scaler, 'ids_scaler.pkl')
joblib.dump({
    'feature_names': list(X.columns),
    'n_features': X.shape[1],
    'label_encoders': label_encoders
}, 'ids_model_config.pkl')
print("[+] Success! AI is trained and saved.")
print(f"[+] Model expects {X.shape[1]} features")
print("[+] Config saved to ids_model_config.pkl")
