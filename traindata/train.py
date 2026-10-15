import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import xgboost as xgb
# Drop columns that can cause data leakage (check your specific CSV's column names)

# ==========================================
# 1. Load the Dataset
# ==========================================
# Note: CICIDS2017 on Kaggle often comes in multiple CSVs. You can load a specific one 
# (e.g., 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv') or a merged version.
file_path = 'combine.csv' 
print(f"Loading data from {file_path}...")
df = pd.read_csv(file_path)

# ==========================================
# 2. Data Cleaning (Specific to CICIDS2017)
# ==========================================
print("Cleaning data...")
leaky_columns = ['Destination Port', 'Source IP', 'Destination IP', 'Source Port', 'Timestamp']
columns_to_drop = [col for col in leaky_columns if col in df.columns]
df.drop(columns=columns_to_drop, inplace=True)

# 2.1 Strip whitespaces from column names 
# The dataset famously has spaces in column names like ' Destination Port'
df.columns = df.columns.str.strip()

# 2.2 Handle Infinity and NaN values
# Network flow calculations sometimes result in dividing by zero
df.replace([np.inf, -np.inf], np.nan, inplace=True)

# Since the dataset is massive, dropping NaN rows is standard and results in minimal data loss
df.dropna(inplace=True)

# 2.3 Drop duplicate rows to prevent data leakage and overfitting
df.drop_duplicates(inplace=True)

# ==========================================
# 3. Preprocessing
# ==========================================
print("Preprocessing features and labels...")

# Separate features (X) and target (y)
# The target column is named 'Label'
X = df.drop(columns=['Label'])
y = df['Label']

# Encode the target labels (e.g., 'BENIGN' -> 0, 'DDoS' -> 1, etc.)
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

# Split into Training (80%) and Testing (20%) sets
# Stratify ensures the distribution of attacks remains balanced across train/test splits
X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)

# Feature Scaling
# XGBoost doesn't strictly require scaling, but it helps with large continuous values in network data
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# ==========================================
# 4. Train XGBoost Model
# ==========================================
print("Training XGBoost model...")

from sklearn.utils.class_weight import compute_sample_weight

# Calculate weights based on the training labels to handle imbalance
weights = compute_sample_weight('balanced', y_train)

# Initialize ONE regularized model
model = xgb.XGBClassifier(
    objective='multi:softprob',
    n_estimators=100,
    learning_rate=0.05,        # Lower learning rate forces the model to learn slower
    max_depth=3,               # Reduce tree depth to prevent complex memorization
    min_child_weight=5,        # Require more samples in a node before splitting
    gamma=0.1,                 # Minimum loss reduction required to make a further partition
    subsample=0.8,             # Train each tree on only 80% of the rows
    colsample_bytree=0.8,      # Train each tree on only 80% of the columns
    random_state=42,
    n_jobs=-1,
    eval_metric='mlogloss'
)

# Fit the model ONCE, ensuring we pass the sample_weights
model.fit(X_train_scaled, y_train, sample_weight=weights)


# ==========================================
# 5. Evaluation
# ==========================================
print("Evaluating the model...")

# Make predictions
y_pred = model.predict(X_test_scaled)

# Calculate Accuracy
accuracy = accuracy_score(y_test, y_pred)
print(f"\nModel Accuracy: {accuracy * 100:.2f}%")

# Generate Classification Report
# We map the encoded numeric labels back to their original string names for readability
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

import joblib

# Save the trained model to a .pkl file
model_filename = 'xgboost_cicids2017_model.pkl'
joblib.dump(model, model_filename)

print(f"\nModel successfully saved as {model_filename}")

import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay

print("\nGenerating Confusion Matrix...")

# 1. Calculate the raw matrix numbers using your true labels and predictions
cm = confusion_matrix(y_test, y_pred)

# 2. Create the display object, attaching your actual attack names (classes)
disp = ConfusionMatrixDisplay(
    confusion_matrix=cm, 
    display_labels=label_encoder.classes_
)

# 3. Plot the matrix (set figure size large enough to fit all CICIDS labels)
fig, ax = plt.subplots(figsize=(14, 10))
disp.plot(cmap=plt.cm.Blues, ax=ax, xticks_rotation=45)

plt.title('Confusion Matrix - CICIDS2017 Classification')
plt.tight_layout()

# 4. Save the chart as an image in your folder and display it
plt.savefig('confusion_matrix.png', dpi=300)
plt.show()