import joblib
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_FILE = BASE_DIR / "models" / "network_risk_model.pkl"
MODEL = joblib.load(MODEL_FILE)
def predict_network_risk(port, protocol, service, version, os_name, open_ports):
    data = pd.DataFrame([{
        "port": port,
        "protocol": protocol,
        "service": service,
        "version": version,
        "os": os_name,
        "open_ports": open_ports
    }])
    prediction = MODEL.predict(data)[0]
    probabilities = MODEL.predict_proba(data)[0]
    confidence = round(max(probabilities) * 100, 2)
    return {
        "risk": prediction,
        "confidence": confidence
    }
if __name__ == "__main__":

    result = predict_network_risk(
        port=80,
        protocol="tcp",
        service="http",
        version="Apache 2.4.49",
        os_name="Linux",
        open_ports=8
    )
    print("\nPrediction Result\n")
    print(result)