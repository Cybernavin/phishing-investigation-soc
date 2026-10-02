import hashlib
from pathlib import Path


def calculate_hash(file_path):
    """Calculate SHA-256 and MD5 hashes."""

    sha256 = hashlib.sha256()
    md5 = hashlib.md5()

    with open(file_path, "rb") as file:

        while True:

            data = file.read(4096)

            if not data:
                break

            sha256.update(data)
            md5.update(data)

    return {
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest()
    }


def analyze_attachment(file_path):
    """Analyze one attachment."""

    file_path = Path(file_path)

    if not file_path.exists():
        return {
            "status": "error",
            "message": "Attachment was not found."
        }

    hashes = calculate_hash(file_path)

    return {
        "status": "success",
        "filename": file_path.name,
        "size": file_path.stat().st_size,
        "extension": file_path.suffix.lower(),
        "sha256": hashes["sha256"],
        "md5": hashes["md5"]
    }


def analyze_attachments(file_paths):
    """Analyze multiple attachments."""

    results = []

    for file_path in file_paths:

        result = analyze_attachment(file_path)

        results.append(result)

    return results