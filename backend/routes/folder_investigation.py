import os
import shutil
import tempfile
import uuid
import zipfile

from flask import Blueprint, jsonify, request

from agents.folder_agent import FolderInvestigationAgent

folder_investigation_bp = Blueprint("folder_investigation", __name__)


@folder_investigation_bp.route("/analyze-folder", methods=["POST"])
def analyze_folder():
    if "evidence_zip" not in request.files:
        return jsonify({
            "success": False,
            "message": "Upload a ZIP archive created from the evidence folder."
        }), 400

    archive = request.files["evidence_zip"]
    if not archive.filename:
        return jsonify({"success": False, "message": "Empty archive name."}), 400

    case_id = f"CASE-{uuid.uuid4().hex[:10].upper()}"
    case_root = os.path.abspath(os.path.join("uploads", "cases", case_id))
    os.makedirs(case_root, exist_ok=True)
    archive_path = os.path.join(case_root, "evidence.zip")

    try:
        archive.save(archive_path)
        with zipfile.ZipFile(archive_path, "r") as zf:
            FolderInvestigationAgent.safe_extract(zf, case_root)

        # Do not analyze the uploaded archive itself as evidence.
        try:
            os.remove(archive_path)
        except OSError:
            pass

        folder_name = request.form.get("folder_name", "Evidence Folder")
        result = FolderInvestigationAgent().analyze_case(
            case_root,
            folder_name
        )
        return jsonify({
            "success": True,
            "analysis": result,
            "report": result.get("report")
        }), 200

    except zipfile.BadZipFile:
        shutil.rmtree(case_root, ignore_errors=True)
        return jsonify({"success": False, "message": "Invalid ZIP archive."}), 400
    except Exception as exc:
        shutil.rmtree(case_root, ignore_errors=True)
        return jsonify({"success": False, "message": str(exc)}), 500
