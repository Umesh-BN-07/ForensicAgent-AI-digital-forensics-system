import os
import uuid

from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename

from agents.evidence_agent import EvidenceAgent
from config import (
    UPLOAD_FOLDER,
    ALLOWED_EXTENSIONS,
    MAX_FILE_SIZE
)


evidence_bp = Blueprint(
    "evidence",
    __name__
)


agent = EvidenceAgent(UPLOAD_FOLDER)


def allowed_file(filename):

    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


@evidence_bp.route("/upload", methods=["POST"])
def upload_evidence():

    if "file" not in request.files:

        return jsonify({
            "success": False,
            "message": "No evidence file provided"
        }), 400

    file = request.files["file"]

    if file.filename == "":

        return jsonify({
            "success": False,
            "message": "No file selected"
        }), 400

    if not allowed_file(file.filename):

        return jsonify({
            "success": False,
            "message": "Unsupported file type"
        }), 400

    # Check file size
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)

    if file_size > MAX_FILE_SIZE:

        return jsonify({
            "success": False,
            "message": "File exceeds 20 MB limit"
        }), 400

    original_filename = secure_filename(file.filename)

    # Prevent files with the same name from overwriting each other
    unique_filename = (
        str(uuid.uuid4())
        + "_"
        + original_filename
    )

    save_path = os.path.join(
        UPLOAD_FOLDER,
        unique_filename
    )

    file.save(save_path)

    evidence = agent.collect_evidence(
        save_path,
        original_filename
    )

    return jsonify({
        "success": True,
        "message": "Evidence uploaded successfully",
        "evidence": evidence
    }), 201