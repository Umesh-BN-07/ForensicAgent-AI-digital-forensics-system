import os
import subprocess
import sys
import tempfile
import zipfile

import requests

BASE_URL = "http://127.0.0.1:5000"
TIMEOUT = 300


def check_backend():
    response = requests.get(f"{BASE_URL}/api/health", timeout=5)
    response.raise_for_status()
    return response.json()


def upload_file(filepath):
    if not os.path.isfile(filepath):
        raise FileNotFoundError(filepath)

    with open(filepath, "rb") as file:
        response = requests.post(
            f"{BASE_URL}/api/evidence/upload",
            files={"file": (os.path.basename(filepath), file)},
            timeout=TIMEOUT
        )

    response.raise_for_status()
    return response.json()


def analyze_log(filename):
    response = requests.post(
        f"{BASE_URL}/api/investigation/analyze-log",
        json={"filename": filename},
        timeout=TIMEOUT
    )
    response.raise_for_status()
    return response.json()


def _build_folder_zip(folder_path):
    """Create a temporary ZIP preserving the complete folder structure."""
    if not os.path.isdir(folder_path):
        raise NotADirectoryError(folder_path)

    temp = tempfile.NamedTemporaryFile(
        prefix="forensic_evidence_",
        suffix=".zip",
        delete=False
    )
    temp.close()

    root_name = os.path.basename(os.path.normpath(folder_path)) or "Evidence"

    try:
        with zipfile.ZipFile(
            temp.name,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=6
        ) as archive:
            for root, _, files in os.walk(folder_path):
                for filename in files:
                    path = os.path.join(root, filename)
                    if os.path.isfile(path):
                        relative = os.path.relpath(path, folder_path)
                        archive_name = os.path.join(root_name, relative)
                        archive.write(path, archive_name)

        return temp.name
    except Exception:
        try:
            os.remove(temp.name)
        except OSError:
            pass
        raise


def analyze_folder(folder_path):
    """Send an entire evidence folder to the backend for autonomous analysis."""
    zip_path = _build_folder_zip(folder_path)
    folder_name = os.path.basename(os.path.normpath(folder_path)) or "Evidence"

    try:
        with open(zip_path, "rb") as archive:
            response = requests.post(
                f"{BASE_URL}/api/investigation/analyze-folder",
                files={
                    "evidence_zip": (
                        f"{folder_name}.zip",
                        archive,
                        "application/zip"
                    )
                },
                data={"folder_name": folder_name},
                timeout=TIMEOUT
            )

        response.raise_for_status()
        return response.json()
    finally:
        try:
            os.remove(zip_path)
        except OSError:
            pass


def open_report(report_path):
    if not report_path:
        raise FileNotFoundError("No report path was returned.")

    candidates = []

    if os.path.isabs(report_path):
        candidates.append(report_path)
    else:
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        normalized = report_path.replace("/", os.sep).replace("\\", os.sep)
        candidates.extend([
            os.path.join(project_root, "backend", normalized),
            os.path.join(project_root, normalized),
            os.path.join(project_root, "backend", "reports", os.path.basename(normalized)),
        ])

    for path in candidates:
        path = os.path.abspath(path)
        if os.path.isfile(path):
            if sys.platform.startswith("win"):
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
            return path

    raise FileNotFoundError(
        "Report PDF was not found.\n\nChecked:\n" +
        "\n".join(os.path.abspath(p) for p in candidates)
    )
