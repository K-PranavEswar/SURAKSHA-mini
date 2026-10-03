import joblib
import pandas as pd
from pathlib import Path

# -----------------------------------------
# Load Models
# -----------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

RF_MODEL_PATH = BASE_DIR / "models" / "network_risk_model.pkl"

RISK_LABELS = {
    0: "Low",
    1: "Medium",
    2: "High",
    3: "Critical"
}

try:
    RF_MODEL = joblib.load(RF_MODEL_PATH)
    print("✅ Random Forest Model Loaded")
except Exception as e:
    print(f"❌ Random Forest Load Error : {e}")
    RF_MODEL = None



# -----------------------------------------
# Predict Using One Model
# -----------------------------------------

def predict_model(model, features):

    if model is None:
        return None

    risk = model.predict(features)[0]

    # Convert numeric prediction to label (if model returns numeric classes)
    if not isinstance(risk, str):
        risk = RISK_LABELS.get(int(risk), "Unknown")

    confidence = 100.0

    if hasattr(model, "predict_proba"):

        probability = model.predict_proba(features)[0]

        confidence = round(max(probability) * 100, 2)

    return {
        "risk": risk,
        "confidence": confidence
    }


# -----------------------------------------
# AI Risk Prediction
# -----------------------------------------

def predict_ai_risk(
    port,
    protocol,
    service,
    version,
    os_name,
    open_ports
):

    features = pd.DataFrame([{
        "port": int(port),
        "protocol": str(protocol).lower(),
        "service": str(service).lower(),
        "version": str(version),
        "os": str(os_name),
        "open_ports": int(open_ports)
    }])

    rf = predict_model(RF_MODEL, features)

    if not rf:
        return {
            "risk": "Unknown",
            "confidence": 0,
            "algorithm": "None",
            "random_forest": None
        }

    # Ensure algorithm label and return RF prediction
    rf["algorithm"] = "Random Forest"

    print("\n========== AI PREDICTION ==========")
    print("Random Forest :", rf)
    print("===================================\n")

    return rf


# -----------------------------------------
# Overall Network Risk
# -----------------------------------------

def overall_network_risk(results):

    if not results:
        return {
            "risk": "Low",
            "confidence": 100
        }

    severity = {
        "Low": 1,
        "Medium": 2,
        "High": 3,
        "Critical": 4
    }

    total = 0
    confidence = 0

    for item in results:

        total += severity.get(
            item.get("ai_risk", "Low"),
            1
        )

        confidence += item.get(
            "confidence",
            0
        )

    average = total / len(results)

    if average >= 3.5:
        risk = "Critical"
    elif average >= 2.5:
        risk = "High"
    elif average >= 1.5:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "risk": risk,
        "confidence": round(
            confidence / len(results),
            2
        )
    }