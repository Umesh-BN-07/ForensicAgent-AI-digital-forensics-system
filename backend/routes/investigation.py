import os

from flask import (
    Blueprint,
    request,
    jsonify
)

from agents.orchestrator import InvestigationOrchestrator
from config import UPLOAD_FOLDER


investigation_bp = Blueprint(
    "investigation",
    __name__
)


orchestrator = InvestigationOrchestrator()


@investigation_bp.route(
    "/analyze-log",
    methods=["POST"]
)
def analyze_log():

    data = request.get_json()

    if not data:

        return jsonify({
            "success": False,
            "message": "JSON body required"
        }), 400

    filename = data.get("filename")

    if not filename:

        return jsonify({
            "success": False,
            "message": "Filename is required"
        }), 400

    # Prevent directory traversal
    safe_filename = os.path.basename(
        filename
    )

    file_path = os.path.join(
        UPLOAD_FOLDER,
        safe_filename
    )

    if not os.path.exists(file_path):

        return jsonify({
            "success": False,
            "message": "Evidence file not found"
        }), 404

    try:

        result = orchestrator.investigate_log(file_path)

        return jsonify({
        "success": True,
        "analysis": result,
        "report": result["report"]
    }), 200

    except Exception as error:

        return jsonify({
            "success": False,
            "message": str(error)
        }), 500