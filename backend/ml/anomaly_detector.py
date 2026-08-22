import joblib
import os

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

MODEL_PATH = os.path.join(
    BASE_DIR,
    "..",
    "models",
    "isolation_forest.pkl"
)


class AnomalyDetector:

    def __init__(self):

        self.model = joblib.load(MODEL_PATH)

    def predict(
        self,
        failed_logins,
        file_access,
        file_download,
        log_delete
    ):

        features = [[
            failed_logins,
            file_access,
            file_download,
            log_delete
        ]]

        prediction = self.model.predict(features)[0]

        score = self.model.decision_function(features)[0]

        return {
            "prediction":
                "ANOMALY"
                if prediction == -1
                else "NORMAL",

            "confidence":
                round(abs(score) * 100, 2)
        }