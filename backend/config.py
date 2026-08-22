import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

ALLOWED_EXTENSIONS = {
    "txt",
    "log",
    "csv"
}

MAX_FILE_SIZE = 20 * 1024 * 1024
