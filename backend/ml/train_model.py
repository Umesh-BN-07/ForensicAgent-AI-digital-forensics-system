import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DATASET = os.path.join(BASE_DIR, "..", "datasets", "login_activity.csv")
MODEL_DIR = os.path.join(BASE_DIR, "..", "models")

os.makedirs(MODEL_DIR, exist_ok=True)

df = pd.read_csv(DATASET)

X = df[
    [
        "failed_logins",
        "file_access",
        "file_download",
        "log_delete"
    ]
]

model = IsolationForest(
    contamination=0.25,
    random_state=42
)

model.fit(X)

joblib.dump(
    model,
    os.path.join(MODEL_DIR, "isolation_forest.pkl")
)

print("Model trained successfully!")