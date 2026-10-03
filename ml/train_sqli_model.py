import joblib
import pandas as pd

from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


# -----------------------------------------
# Paths
# -----------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

DATASET = BASE_DIR / "datasets" / "sqli.csv"
MODEL_DIR = BASE_DIR / "models"

MODEL_DIR.mkdir(exist_ok=True)

MODEL_FILE = MODEL_DIR / "sqli_model.pkl"


# -----------------------------------------
# Load Dataset
# -----------------------------------------

print("\nLoading SQL Injection Dataset...")

df = pd.read_csv(
    DATASET,
    encoding="utf-16"
)

print(f"Dataset Size : {len(df)}")
print("\nColumns:")
print(df.columns.tolist())


# -----------------------------------------
# Clean Dataset
# -----------------------------------------

df = df.dropna(
    subset=["Sentence", "Label"]
)

df["Sentence"] = (
    df["Sentence"]
    .astype(str)
    .str.strip()
)

df["Label"] = pd.to_numeric(
    df["Label"],
    errors="coerce"
)

df = df.dropna(
    subset=["Label"]
)

df["Label"] = df["Label"].astype(int)


# -----------------------------------------
# Features / Target
# -----------------------------------------

X = df["Sentence"]
y = df["Label"]


print("\nLabel Distribution:")
print(y.value_counts())


# -----------------------------------------
# Train / Test Split
# -----------------------------------------

X_train, X_test, y_train, y_test = train_test_split(

    X,
    y,

    test_size=0.30,

    random_state=42,

    stratify=y
)


print("\nTraining Samples :", len(X_train))
print("Testing Samples  :", len(X_test))


# -----------------------------------------
# TF-IDF + Random Forest
# -----------------------------------------

model = Pipeline([

    (
        "tfidf",

        TfidfVectorizer(

            analyzer="char",

            ngram_range=(2, 5),

            min_df=2,

            max_features=10000,

            sublinear_tf=True
        )
    ),

    (
        "classifier",

        RandomForestClassifier(

            n_estimators=200,

            max_depth=15,

            min_samples_split=5,

            min_samples_leaf=2,

            max_features="sqrt",

            class_weight="balanced",

            random_state=42,

            n_jobs=-1
        )
    )

])


# -----------------------------------------
# Training
# -----------------------------------------

print("\nTraining SQL Injection Model...\n")

model.fit(
    X_train,
    y_train
)


# -----------------------------------------
# Prediction
# -----------------------------------------

predictions = model.predict(
    X_test
)


# -----------------------------------------
# Evaluation
# -----------------------------------------

accuracy = accuracy_score(
    y_test,
    predictions
)

precision = precision_score(
    y_test,
    predictions,
    average="weighted",
    zero_division=0
)

recall = recall_score(
    y_test,
    predictions,
    average="weighted",
    zero_division=0
)

f1 = f1_score(
    y_test,
    predictions,
    average="weighted",
    zero_division=0
)


print("=" * 60)
print("SQL INJECTION MODEL PERFORMANCE")
print("=" * 60)

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
    f"F1-Score  : {f1 * 100:.2f}%"
)


# -----------------------------------------
# Classification Report
# -----------------------------------------

print("\nClassification Report\n")

print(
    classification_report(
        y_test,
        predictions,
        zero_division=0
    )
)


# -----------------------------------------
# Confusion Matrix
# -----------------------------------------

print("Confusion Matrix\n")

print(
    confusion_matrix(
        y_test,
        predictions
    )
)


# -----------------------------------------
# Save Model
# -----------------------------------------

joblib.dump(
    model,
    MODEL_FILE
)

print("\n" + "=" * 60)
print("MODEL SAVED SUCCESSFULLY")
print("=" * 60)

print(MODEL_FILE)