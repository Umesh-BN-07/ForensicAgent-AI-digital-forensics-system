import os
import hashlib
from datetime import datetime, timezone


class EvidenceAgent:
    """
    Evidence Collection Agent

    Responsibilities:
    - Store uploaded evidence
    - Generate SHA-256 hash
    - Collect metadata
    - Preserve evidence integrity
    """

    def __init__(self, upload_folder):
        self.upload_folder = upload_folder

        # Create upload directory if it doesn't exist
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)

    # ---------------------------------------------------
    # Calculate SHA-256 Hash
    # ---------------------------------------------------
    def calculate_hash(self, file_path):
        """
        Calculate SHA-256 hash of the uploaded evidence.
        """

        sha256 = hashlib.sha256()

        with open(file_path, "rb") as file:

            while True:
                chunk = file.read(65536)  # Read 64 KB at a time

                if not chunk:
                    break

                sha256.update(chunk)

        return sha256.hexdigest()

    # ---------------------------------------------------
    # Collect Evidence Metadata
    # ---------------------------------------------------
    def collect_evidence(self, file_path, original_filename):
        """
        Collect metadata about uploaded evidence.
        """

        file_hash = self.calculate_hash(file_path)

        file_size = os.path.getsize(file_path)

        evidence = {
            "filename": original_filename,

            # UUID filename stored on server
            "stored_filename": os.path.basename(file_path),

            # Full storage path
            "stored_path": file_path,

            # File size in bytes
            "file_size": file_size,

            # SHA-256 Integrity Hash
            "sha256": file_hash,

            # Upload timestamp
            "collected_at": datetime.now(timezone.utc).isoformat(),

            # Current evidence status
            "status": "Evidence Collected"
        }

        return evidence

    # ---------------------------------------------------
    # Verify Evidence Integrity
    # ---------------------------------------------------
    def verify_integrity(self, file_path, original_hash):
        """
        Verify that evidence has not been modified.
        """

        current_hash = self.calculate_hash(file_path)

        return current_hash == original_hash

    # ---------------------------------------------------
    # Read Evidence
    # ---------------------------------------------------
    def read_evidence(self, file_path):
        """
        Read uploaded evidence file.
        """

        try:

            with open(
                file_path,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as file:

                return file.read()

        except Exception as e:

            return str(e)