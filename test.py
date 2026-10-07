import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# ============================================================
# SURAKSHA ML MODEL EVALUATION
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODELS_DIR = os.path.join(BASE_DIR, "models")
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")


# ============================================================
# SQL INJECTION MODEL
# ============================================================

def evaluate_sqli():

    print("\n" + "=" * 70)
    print("        SQL INJECTION ML MODEL")
    print("=" * 70)

    model_path = os.path.join(
        MODELS_DIR,
        "sqli_model.pkl"
    )

    dataset_path = os.path.join(
        DATASETS_DIR,
        "sqli.csv"
    )

    if not os.path.exists(model_path):
        print(f"❌ Model not found: {model_path}")
        return

    if not os.path.exists(dataset_path):
        print(f"❌ Dataset not found: {dataset_path}")
        return

    # Load model
    try:
        model = joblib.load(model_path)
        print("✔ Model loaded: sqli_model.pkl")
    except Exception as e:
        print(f"❌ Model loading failed: {e}")
        return

    # Load UTF-16 CSV
    try:
        df = pd.read_csv(
            dataset_path,
            encoding="utf-16"
        )

        print("✔ Dataset loaded: sqli.csv")
        print(f"✔ Original dataset size: {len(df)} rows")

    except Exception as e:
        print(f"❌ Dataset loading failed: {e}")
        return

    # Validate columns
    required_columns = ["Sentence", "Label"]

    for column in required_columns:

        if column not in df.columns:
            print(f"❌ Missing column: {column}")
            print(f"Available columns: {list(df.columns)}")
            return

    # --------------------------------------------------------
    # Clean dataset
    # --------------------------------------------------------

    print("\nDATASET VALIDATION")
    print("-" * 70)

    print(
        f"Missing Sentence values : "
        f"{df['Sentence'].isna().sum()}"
    )

    print(
        f"Missing Label values    : "
        f"{df['Label'].isna().sum()}"
    )

    df = df.dropna(
        subset=["Sentence", "Label"]
    ).copy()

    df["Sentence"] = (
        df["Sentence"]
        .astype(str)
        .str.strip()
    )

    df = df[
        df["Sentence"] != ""
    ].copy()

    df["Label"] = pd.to_numeric(
        df["Label"],
        errors="coerce"
    )

    df = df.dropna(
        subset=["Label"]
    ).copy()

    df["Label"] = df["Label"].astype(int)

    print(
        f"Clean dataset size      : {len(df)} rows"
    )

    print("\nLABEL DISTRIBUTION")
    print("-" * 70)

    print(
        df["Label"]
        .value_counts()
        .sort_index()
    )

    # Features / labels
    X = df["Sentence"]
    y = df["Label"]

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print("\nDATA SPLIT")
    print("-" * 70)
    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples : {len(X_test)}")

    # Prediction
    try:
        y_pred = model.predict(X_test)
    except Exception as e:
        print("\n❌ SQLi prediction failed.")
        print(e)
        return

    # Metrics
    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    precision = precision_score(
        y_test,
        y_pred,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        zero_division=0
    )

    print("\nRESULTS")
    print("-" * 70)

    print(f"Accuracy  : {accuracy * 100:.2f}%")
    print(f"Precision : {precision * 100:.2f}%")
    print(f"Recall    : {recall * 100:.2f}%")
    print(f"F1 Score  : {f1 * 100:.2f}%")

    print("\nCONFUSION MATRIX")
    print("-" * 70)

    print(
        confusion_matrix(
            y_test,
            y_pred
        )
    )

    print("\nCLASSIFICATION REPORT")
    print("-" * 70)

    print(
        classification_report(
            y_test,
            y_pred,
            zero_division=0
        )
    )


# ============================================================
# NETWORK RISK MODEL
# ============================================================

def evaluate_network():

    print("\n" + "=" * 70)
    print("        NETWORK RISK RANDOM FOREST")
    print("=" * 70)

    model_path = os.path.join(
        MODELS_DIR,
        "network_risk_model.pkl"
    )

    # IMPORTANT:
    # This is the cleaned dataset.
    dataset_path = os.path.join(
        DATASETS_DIR,
        "network_risk.csv"
    )

    if not os.path.exists(model_path):
        print(f"❌ Model not found: {model_path}")
        return

    if not os.path.exists(dataset_path):
        print(
            f"❌ Cleaned dataset not found: "
            f"{dataset_path}"
        )
        return

    # Load model
    try:

        model = joblib.load(
            model_path
        )

        print(
            "✔ Model loaded: "
            "network_risk_model.pkl"
        )

    except Exception as e:

        print(
            f"❌ Model loading failed: {e}"
        )

        return

    # Load cleaned dataset
    try:

        df = pd.read_csv(
            dataset_path
        )

        print(
            "✔ Dataset loaded: "
            "network_risk.csv"
        )

        print(
            f"✔ Dataset size: {len(df)} rows"
        )

    except Exception as e:

        print(
            f"❌ Dataset loading failed: {e}"
        )

        return

    # --------------------------------------------------------
    # Validate target
    # --------------------------------------------------------

    target_column = "risk"

    if target_column not in df.columns:

        print(
            f"❌ Target column "
            f"'{target_column}' not found."
        )

        print(
            f"Available columns: "
            f"{list(df.columns)}"
        )

        return

    # --------------------------------------------------------
    # Check missing values
    # --------------------------------------------------------

    print("\nDATASET VALIDATION")
    print("-" * 70)

    missing = df.isnull().sum()

    total_missing = missing.sum()

    print(
        f"Total missing values: {total_missing}"
    )

    if total_missing > 0:

        print("\nMissing values by column:")

        print(
            missing[
                missing > 0
            ]
        )

        df = df.dropna().copy()

    # --------------------------------------------------------
    # Features and target
    # --------------------------------------------------------

    X = df.drop(
        columns=[target_column]
    )

    y = df[target_column]

    # --------------------------------------------------------
    # Label distribution
    # --------------------------------------------------------

    print("\nRISK DISTRIBUTION")
    print("-" * 70)

    print(
        y.value_counts()
    )

    # --------------------------------------------------------
    # Train/test split
    # --------------------------------------------------------

    try:

        X_train, X_test, y_train, y_test = train_test_split(

            X,
            y,

            test_size=0.20,

            random_state=42,

            stratify=y
        )

    except Exception as e:

        print(
            f"❌ Dataset split failed: {e}"
        )

        return

    print("\nDATA SPLIT")
    print("-" * 70)

    print(
        f"Training samples: {len(X_train)}"
    )

    print(
        f"Testing samples : {len(X_test)}"
    )

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    try:

        y_pred = model.predict(
            X_test
        )

    except Exception as e:

        print(
            "\n❌ Network prediction failed."
        )

        print(e)

        print(
            "\n⚠ IMPORTANT:"
        )

        print(
            "The existing model may have been "
            "trained using the original 5,000-row "
            "dataset."
        )

        print(
            "Retrain network_risk_model.pkl "
            "using network_risk.csv "
            "before evaluating the cleaned dataset."
        )

        return

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    precision = precision_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0
    )

    recall = recall_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0
    )

    print("\nRESULTS")
    print("-" * 70)

    print(
        f"Accuracy  : {accuracy * 100:.2f}%"
    )

    print(
        f"Precision : {precision * 100:.2f}%"
    )

    print(
        f"Recall    : {recall * 100:.2f}%"
    )

    print(
        f"F1 Score  : {f1 * 100:.2f}%"
    )

    # --------------------------------------------------------
    # Confusion Matrix
    # --------------------------------------------------------

    print("\nCONFUSION MATRIX")
    print("-" * 70)

    print(
        confusion_matrix(
            y_test,
            y_pred
        )
    )

    # --------------------------------------------------------
    # Classification Report
    # --------------------------------------------------------

    print("\nCLASSIFICATION REPORT")
    print("-" * 70)

    print(
        classification_report(
            y_test,
            y_pred,
            zero_division=0
        )
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print("\n")

    print("=" * 70)
    print("             SURAKSHA ML MODEL EVALUATION")
    print("=" * 70)

    # SQL Injection
    evaluate_sqli()

    # Network Risk
    evaluate_network()

    print("\n")

    print("=" * 70)
    print("                    TEST COMPLETED")
    print("=" * 70)