import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# Load and combine all CSVs
folder_path = "data/"  # your dataset folder
csv_files = [file for file in os.listdir(folder_path) if file.endswith(".csv")]

combined_df = pd.DataFrame()

for file in csv_files:
    print(f"🔄 Loading {file}")
    df = pd.read_csv(os.path.join(folder_path, file), low_memory=False)
    combined_df = pd.concat([combined_df, df], ignore_index=True)

print(f"✅ Combined dataset shape: {combined_df.shape}")

# Rename last column to 'Label' if it's unnamed
if combined_df.columns[-1] not in ["Label", "label"]:
    combined_df.rename(columns={combined_df.columns[-1]: "Label"}, inplace=True)

# Check if 'Label' exists now
if "Label" not in combined_df.columns:
    raise Exception("❌ 'Label' column not found!")

# Drop rows with missing Label
combined_df = combined_df.dropna(subset=["Label"])

# Drop rows with any NaN or inf in numerical features
combined_df.replace([np.inf, -np.inf], np.nan, inplace=True)
combined_df.dropna(inplace=True)

# Encode labels: Benign -> 0, others -> 1
combined_df["Label"] = combined_df["Label"].apply(lambda x: 0 if "benign" in str(x).lower() else 1)

# Drop non-numeric and useless columns (like Timestamp, Flow ID, etc.)
non_numeric_cols = combined_df.select_dtypes(exclude=[np.number]).columns
combined_df.drop(columns=non_numeric_cols, inplace=True)

# Final features and labels
X = combined_df.drop(columns=["Label"]).astype(np.float32)
y = combined_df["Label"]

print(f"✅ Cleaned X shape: {X.shape}, y length: {len(y)}")

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Predict and evaluate
y_pred = model.predict(X_test)
print("✅ Accuracy:", accuracy_score(y_test, y_pred))
print("📄 Classification Report:\n", classification_report(y_test, y_pred))

# Ensure 'model' directory exists
os.makedirs("model", exist_ok=True)

# Save the trained model
joblib.dump(model, "model/rf_model.pkl")
print("✅ Model saved to model/rf_model.pkl")