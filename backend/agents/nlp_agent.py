import spacy

nlp = spacy.load("en_core_web_sm")


class NLPAgent:

    def __init__(self):

        self.keyword_weights = {
    "password": 30,
    "credential": 30,
    "confidential": 25,
    "database": 20,
    "delete": 20,
    "secret": 25,
    "vpn": 15,
    "bitcoin": 30,
    "transfer": 20,
    "urgent": 10,
    "immediately": 10,
    "exploit": 30,
    "attack": 25,
    "malware": 35,
    "ransomware": 40
    }

    def analyze_text(self, text):

        doc = nlp(text.lower())

        detected = []
        score = 0

        for token in doc:
            if token.text in self.keyword_weights:
                detected.append(token.text)
                score += self.keyword_weights[token.text]

        score = min(score, 100)

        if score >= 70:
            risk = "CRITICAL"
        elif score >= 50:
            risk = "HIGH"
        elif score >= 20:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        return {
            "risk": risk,
            "score": score,
            "keywords": detected
        }