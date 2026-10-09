import pandas as pd
import joblib
import matplotlib.pyplot as plt

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
# NETWORK RISK MODEL
# ============================================================

def test_network_model():

    print("\n")
    print("=" * 60)
    print("        NETWORK RISK - RANDOM FOREST")
    print("=" * 60)

    DATASET_PATH = "datasets/network_risk.csv"
    MODEL_PATH = "models/network_risk_model.pkl"

    # Load dataset
    df = pd.read_csv(DATASET_PATH)

    # Remove duplicates
    df = df.drop_duplicates()

    print(f"Dataset shape: {df.shape}")

    features = [
        "port",
        "protocol",
        "service",
        "version",
        "os",
        "open_ports",
        "category"
    ]

    X = df[features]
    y = df["risk"]

    # IMPORTANT:
    # Do NOT use pd.get_dummies().
    # The saved pipeline handles preprocessing.

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    # Load model
    model = joblib.load(MODEL_PATH)

    # Prediction
    y_pred = model.predict(X_test)

    # Metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(
        y_test, y_pred,
        average="weighted",
        zero_division=0
    )
    recall = recall_score(
        y_test, y_pred,
        average="weighted",
        zero_division=0
    )
    f1 = f1_score(
        y_test, y_pred,
        average="weighted",
        zero_division=0
    )

    print("\nMODEL PERFORMANCE")
    print("-" * 40)
    print(f"Test Samples : {len(y_test)}")
    print(f"Accuracy     : {accuracy * 100:.2f}%")
    print(f"Precision    : {precision * 100:.2f}%")
    print(f"Recall       : {recall * 100:.2f}%")
    print(f"F1-Score     : {f1 * 100:.2f}%")

    labels = ["Critical", "High", "Low", "Medium"]

    cm = confusion_matrix(
        y_test,
        y_pred,
        labels=labels
    )

    print("\nCONFUSION MATRIX")
    print(cm)

    print("\nTP / TN / FP / FN")
    print("-" * 40)

    total = cm.sum()

    for i, label in enumerate(labels):

        TP = cm[i, i]
        FN = cm[i, :].sum() - TP
        FP = cm[:, i].sum() - TP
        TN = total - TP - FN - FP

        print(
            f"{label:8} -> "
            f"TP: {TP:3} | "
            f"TN: {TN:3} | "
            f"FP: {FP:3} | "
            f"FN: {FN:3}"
        )

    print("\nCLASSIFICATION REPORT")
    print(classification_report(
        y_test,
        y_pred,
        labels=labels,
        zero_division=0
    ))

    # Plot
    plt.figure(figsize=(8, 6))

    plt.imshow(cm, interpolation="nearest")

    plt.colorbar()

    plt.xticks(
        range(len(labels)),
        labels
    )

    plt.yticks(
        range(len(labels)),
        labels
    )

    for i in range(len(labels)):
        for j in range(len(labels)):
            plt.text(
                j,
                i,
                str(cm[i, j]),
                ha="center",
                va="center",
                color="black"
            )

    plt.xlabel("Predicted Label")
    plt.ylabel("Actual Label")

    plt.title(
        "Network Risk – Random Forest Confusion Matrix"
    )

    plt.tight_layout()

    plt.savefig(
        "network_risk_confusion_matrix.png",
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print(
        "\nSaved: network_risk_confusion_matrix.png"
    )


# ============================================================
# SQL INJECTION MODEL
# ============================================================

def test_sqli_model():

    print("\n")
    print("=" * 60)
    print("        SQL INJECTION - RANDOM FOREST")
    print("=" * 60)

    DATASET_PATH = "datasets/sqli.csv"
    MODEL_PATH = "models/sqli_model.pkl"

    # sqli.csv is UTF-16 encoded
    df = pd.read_csv(
        DATASET_PATH,
        encoding="utf-16"
    )

    print(f"Original dataset shape: {df.shape}")

    # Remove missing/empty sentences
    df = df.dropna(subset=["Sentence", "Label"])

    df["Sentence"] = df["Sentence"].astype(str)

    df = df[
        df["Sentence"].str.strip() != ""
    ]

    print(f"Cleaned dataset shape: {df.shape}")

    X = df["Sentence"]
    y = df["Label"]

    # Convert labels to integer if required
    y = y.astype(int)

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    # Load saved pipeline
    model = joblib.load(MODEL_PATH)

    # Prediction
    y_pred = model.predict(X_test)

    # Metrics
    accuracy = accuracy_score(y_test, y_pred)

    precision = precision_score(
        y_test,
        y_pred,
        average="binary",
        zero_division=0
    )

    recall = recall_score(
        y_test,
        y_pred,
        average="binary",
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        average="binary",
        zero_division=0
    )

    print("\nMODEL PERFORMANCE")
    print("-" * 40)
    print(f"Test Samples : {len(y_test)}")
    print(f"Accuracy     : {accuracy * 100:.2f}%")
    print(f"Precision    : {precision * 100:.2f}%")
    print(f"Recall       : {recall * 100:.2f}%")
    print(f"F1-Score     : {f1 * 100:.2f}%")

    # Confusion matrix
    labels = [0, 1]

    cm = confusion_matrix(
        y_test,
        y_pred,
        labels=labels
    )

    print("\nCONFUSION MATRIX")
    print(cm)

    # Binary TP/TN/FP/FN
    TN = cm[0, 0]
    FP = cm[0, 1]
    FN = cm[1, 0]
    TP = cm[1, 1]

    print("\nTP / TN / FP / FN")
    print("-" * 40)
    print(f"TP: {TP}")
    print(f"TN: {TN}")
    print(f"FP: {FP}")
    print(f"FN: {FN}")

    print("\nCLASSIFICATION REPORT")

    print(
        classification_report(
            y_test,
            y_pred,
            labels=[0, 1],
            target_names=[
                "Normal",
                "SQL Injection"
            ],
            zero_division=0
        )
    )

    # Plot
    matrix_labels = [
        "Normal",
        "SQL Injection"
    ]

    plt.figure(figsize=(7, 6))

    plt.imshow(
        cm,
        interpolation="nearest"
    )

    plt.colorbar()

    plt.xticks(
        range(2),
        matrix_labels
    )

    plt.yticks(
        range(2),
        matrix_labels
    )

    for i in range(2):
        for j in range(2):
            plt.text(
                j,
                i,
                str(cm[i, j]),
                ha="center",
                va="center",
                color="black"
            )

    plt.xlabel("Predicted Label")
    plt.ylabel("Actual Label")

    plt.title(
        "SQL Injection – Random Forest Confusion Matrix"
    )

    plt.tight_layout()

    plt.savefig(
        "sqli_confusion_matrix.png",
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print(
        "\nSaved: sqli_confusion_matrix.png"
    )


# ============================================================
# RUN BOTH MODELS
# ============================================================

if __name__ == "__main__":

    test_network_model()

    test_sqli_model()

    print("\n")
    print("=" * 60)
    print("       ALL MODEL TESTS COMPLETED")
    print("=" * 60)