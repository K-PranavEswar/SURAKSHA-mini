import json
import joblib
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

BASE_DIR = Path(__file__).resolve().parent.parent
TRAINING_FILE = BASE_DIR / "scanner" / "training.json"
MODEL_FILE = BASE_DIR / "models" / "web_scan_model.pkl"

FEATURES = ["missing_headers", "sensitive_paths", "sql_indicators", "xss_indicators", 
            "https_disabled", "server_disclosure"]
LABEL = "risk"
RISK_MAP = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

def load_dataset():
    if not TRAINING_FILE.exists():
        raise FileNotFoundError(f"Training dataset not found: {TRAINING_FILE}")
    with open(TRAINING_FILE, "r") as f:
        data = json.load(f)
    return pd.DataFrame(data)

def preprocess(df):
    for col in FEATURES:
        if col not in df.columns:
            raise ValueError(f"Missing column: {col}")
    if LABEL not in df.columns:
        raise ValueError(f"Missing label column: {LABEL}")
    x = df[FEATURES]
    y = df[LABEL].map(RISK_MAP)
    return x, y

def train_model(x, y):
    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=0.2,
        random_state=42
    )
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        random_state=42
    )
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    accuracy = accuracy_score(y_test, predictions)
    return model, accuracy

def save_model(model):
    MODEL_FILE.parent.mkdir(exist_ok=True)
    joblib.dump(model, MODEL_FILE)

def main():
    print("\n============= MODEL TRAINING =============\n")
    print("[+] Loading training dataset...")
    df = load_dataset()
    print(f"[+] Dataset Loaded: {len(df)} samples")
    print("[+] Extracting features...")
    x, y = preprocess(df)
    print("[+] Training RandomForest model...")
    model, accuracy = train_model(x, y)
    print("[+] Saving trained model...")
    save_model(model)
    print("\n============= TRAINING COMPLETE =============\n")
    print(f"[✓] Accuracy      : {accuracy * 100:.2f}%")
    print(f"[✓] Samples       : {len(df)}")
    print(f"[✓] Features      : {len(FEATURES)}")
    print(f"[✓] Model Saved   : {MODEL_FILE}")

if __name__ == "__main__":
    main()