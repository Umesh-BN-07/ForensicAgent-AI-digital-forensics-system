from flask import Blueprint, request, jsonify
from agents.nlp_agent import NLPAgent

nlp_bp = Blueprint("nlp", __name__)

agent = NLPAgent()


@nlp_bp.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json()

    if not data or "text" not in data:

        return jsonify({
            "success": False,
            "message": "Text is required."
        }), 400

    result = agent.analyze_text(data["text"])

    return jsonify({
        "success": True,
        "analysis": result
    })