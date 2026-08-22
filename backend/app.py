from flask import Flask, jsonify
from flask_cors import CORS

from routes.evidence import evidence_bp
from routes.investigation import investigation_bp
from routes.nlp import nlp_bp
from routes.folder_investigation import folder_investigation_bp


def create_app():
    app = Flask(__name__)
    CORS(app)

    # Allow reasonably large evidence archives for folder investigations.
    app.config["MAX_CONTENT_LENGTH"] = 300 * 1024 * 1024

    app.register_blueprint(evidence_bp, url_prefix="/api/evidence")
    app.register_blueprint(investigation_bp, url_prefix="/api/investigation")
    app.register_blueprint(nlp_bp, url_prefix="/api/nlp")
    app.register_blueprint(folder_investigation_bp, url_prefix="/api/investigation")

    @app.route("/")
    def home():
        return jsonify({
            "project": "ForensicAgent",
            "description": "AI Agent for Automated Digital Forensics Investigation",
            "status": "running"
        })

    @app.route("/api/health")
    def health():
        return jsonify({"status": "healthy"})

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
