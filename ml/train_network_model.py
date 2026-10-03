import joblib
import pandas as pd
from pathlib import Path

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score
)
from sklearn.model_selection import (
    train_test_split,
    cross_val_score
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

# --------------------------------------------------------
# Paths
# --------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

DATASET = BASE_DIR / "datasets" / "network_risk_dataset.csv"

MODEL_DIR = BASE_DIR / "models"
MODEL_DIR.mkdir(exist_ok=True)

MODEL_FILE = MODEL_DIR / "network_risk_model.pkl"

# --------------------------------------------------------
# Load Dataset
# --------------------------------------------------------

df = pd.read_csv(DATASET)

# Shuffle dataset
df = df.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)

print("\nDataset Loaded Successfully\n")
print(df.head())

# --------------------------------------------------------
# Features & Target
# --------------------------------------------------------

X = df[
    [
        "port",
        "protocol",
        "service",
        "version",
        "os",
        "open_ports"
    ]
]

y = df["risk"]

# --------------------------------------------------------
# Train/Test Split
# --------------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    stratify=y,
    random_state=42
)

# --------------------------------------------------------
# Preprocessing
# --------------------------------------------------------

categorical = [
    "protocol",
    "service",
    "version",
    "os"
]

numeric = [
    "port",
    "open_ports"
]

preprocessor = ColumnTransformer(
    transformers=[
        (
            "cat",
            OneHotEncoder(handle_unknown="ignore"),
            categorical
        ),
        (
            "num",
            "passthrough",
            numeric
        )
    ]
)

# --------------------------------------------------------
# Model
# --------------------------------------------------------

classifier = RandomForestClassifier(
    n_estimators=100,
    max_depth=8,
    min_samples_split=10,
    min_samples_leaf=5,
    max_features="sqrt",
    bootstrap=True,
    random_state=42
)

model = Pipeline(
    steps=[
        ("preprocessor", preprocessor),
        ("classifier", classifier)
    ]
)

# --------------------------------------------------------
# Training
# --------------------------------------------------------

print("\nTraining Model...\n")

model.fit(
    X_train,
    y_train
)

# --------------------------------------------------------
# Cross Validation
# --------------------------------------------------------

cv_scores = cross_val_score(
    model,
    X,
    y,
    cv=5,
    scoring="accuracy"
)

# --------------------------------------------------------
# Prediction
# --------------------------------------------------------

predictions = model.predict(X_test)

accuracy = accuracy_score(
    y_test,
    predictions
)

precision = precision_score(
    y_test,
    predictions,
    average="weighted"
)

recall = recall_score(
    y_test,
    predictions,
    average="weighted"
)

f1 = f1_score(
    y_test,
    predictions,
    average="weighted"
)

# --------------------------------------------------------
# Results
# --------------------------------------------------------

print("=" * 60)
print("MODEL PERFORMANCE")
print("=" * 60)

print(f"\nAccuracy        : {accuracy * 100:.2f}%")
print(f"Precision       : {precision * 100:.2f}%")
print(f"Recall          : {recall * 100:.2f}%")
print(f"F1-Score        : {f1 * 100:.2f}%")

print("\nCross Validation Accuracy")

for i, score in enumerate(cv_scores, start=1):
    print(f"Fold {i} : {score * 100:.2f}%")

print(
    f"\nAverage CV Accuracy : {cv_scores.mean() * 100:.2f}%"
)

print("\nClassification Report\n")

print(
    classification_report(
        y_test,
        predictions
    )
)

print("Confusion Matrix\n")

print(
    confusion_matrix(
        y_test,
        predictions
    )
)

# --------------------------------------------------------
# Save Model
# --------------------------------------------------------

joblib.dump(
    model,
    MODEL_FILE
)

print("\nModel Saved Successfully")
print(MODEL_FILE)