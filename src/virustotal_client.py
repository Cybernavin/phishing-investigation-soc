import base64
import time
import requests


# ============================================================
# VirusTotal API Key
# ============================================================

API_KEY = "0d5f76b3d5153e8519e20d37bb374999"

BASE_URL = "https://www.virustotal.com/api/v3"


# ============================================================
# Helper Functions
# ============================================================

def get_headers():
    """Return headers required by the VirusTotal API."""

    return {
        "x-apikey": API_KEY
    }


def encode_url(url):
    """
    Encode a URL into the identifier required
    by the VirusTotal API.
    """

    encoded = base64.urlsafe_b64encode(
        url.encode()
    ).decode().strip("=")

    return encoded


# ============================================================
# Get Existing URL Report
# ============================================================

def get_url_report(url):
    """Check whether VirusTotal already has a URL report."""

    url_id = encode_url(url)

    endpoint = (
        f"{BASE_URL}/urls/{url_id}"
    )

    try:

        response = requests.get(
            endpoint,
            headers=get_headers(),
            timeout=30
        )

        if response.status_code == 200:

            data = response.json()

            attributes = (
                data.get("data", {})
                .get("attributes", {})
            )

            stats = attributes.get(
                "last_analysis_stats",
                {}
            )

            return {
                "status": "found",
                "type": "url",
                "url": url,
                "malicious": stats.get(
                    "malicious",
                    0
                ),
                "suspicious": stats.get(
                    "suspicious",
                    0
                ),
                "harmless": stats.get(
                    "harmless",
                    0
                ),
                "undetected": stats.get(
                    "undetected",
                    0
                )
            }

        if response.status_code == 404:

            return {
                "status": "not_found",
                "type": "url",
                "url": url
            }

        if response.status_code == 429:

            return {
                "status": "rate_limited",
                "type": "url",
                "url": url,
                "message": (
                    "VirusTotal API rate limit reached."
                )
            }

        return {
            "status": "error",
            "type": "url",
            "url": url,
            "message": (
                f"VirusTotal returned "
                f"HTTP {response.status_code}"
            )
        }

    except requests.RequestException as error:

        return {
            "status": "error",
            "type": "url",
            "url": url,
            "message": str(error)
        }


# ============================================================
# Submit URL
# ============================================================

def submit_url(url):
    """Submit a URL to VirusTotal."""

    endpoint = (
        f"{BASE_URL}/urls"
    )

    try:

        response = requests.post(
            endpoint,
            headers={
                **get_headers(),
                "Content-Type": (
                    "application/x-www-form-urlencoded"
                )
            },
            data={
                "url": url
            },
            timeout=30
        )

        if response.status_code in [200, 201]:

            data = response.json()

            analysis_id = (
                data.get("data", {})
                .get("id")
            )

            return {
                "status": "submitted",
                "type": "url",
                "url": url,
                "analysis_id": analysis_id
            }

        if response.status_code == 429:

            return {
                "status": "rate_limited",
                "type": "url",
                "url": url,
                "message": (
                    "VirusTotal API rate limit reached."
                )
            }

        return {
            "status": "error",
            "type": "url",
            "url": url,
            "message": (
                f"VirusTotal returned "
                f"HTTP {response.status_code}"
            )
        }

    except requests.RequestException as error:

        return {
            "status": "error",
            "type": "url",
            "url": url,
            "message": str(error)
        }


# ============================================================
# Get Analysis
# ============================================================

def get_analysis(analysis_id):
    """Get the status of a VirusTotal analysis."""

    if not analysis_id:

        return {
            "status": "error",
            "message": "No analysis ID was provided."
        }

    endpoint = (
        f"{BASE_URL}/analyses/{analysis_id}"
    )

    try:

        response = requests.get(
            endpoint,
            headers=get_headers(),
            timeout=30
        )

        if response.status_code == 200:

            data = response.json()

            attributes = (
                data.get("data", {})
                .get("attributes", {})
            )

            return {
                "status": "success",
                "analysis_status": attributes.get(
                    "status",
                    "unknown"
                ),
                "data": data
            }

        if response.status_code == 429:

            return {
                "status": "rate_limited",
                "message": (
                    "VirusTotal API rate limit reached."
                )
            }

        return {
            "status": "error",
            "message": (
                f"VirusTotal returned "
                f"HTTP {response.status_code}"
            )
        }

    except requests.RequestException as error:

        return {
            "status": "error",
            "message": str(error)
        }


# ============================================================
# Wait For Analysis
# ============================================================

def wait_for_analysis(
    analysis_id,
    max_attempts=3,
    wait_seconds=15
):
    """
    Wait for a VirusTotal analysis to finish.

    A small polling limit is used because public/free
    VirusTotal API access is rate limited.
    """

    if not analysis_id:

        return {
            "status": "error",
            "message": "No analysis ID was provided."
        }

    for attempt in range(
        1,
        max_attempts + 1
    ):

        result = get_analysis(
            analysis_id
        )

        if result["status"] != "success":
            return result

        analysis_status = result.get(
            "analysis_status",
            "unknown"
        )

        if analysis_status == "completed":

            return result

        if attempt < max_attempts:

            time.sleep(
                wait_seconds
            )

    return {
        "status": "pending",
        "analysis_id": analysis_id,
        "message": (
            "VirusTotal analysis did not complete "
            "within the configured polling period."
        )
    }


# ============================================================
# Check URL
# ============================================================

def check_url(url):
    """
    Check a URL using VirusTotal.

    Workflow:

    1. Check existing report.
    2. If no report exists, submit URL.
    3. Wait for analysis.
    4. Retrieve final URL report.
    """

    existing_report = get_url_report(
        url
    )

    if existing_report["status"] == "found":

        return existing_report

    if existing_report["status"] in {
        "rate_limited",
        "error"
    }:

        return existing_report

    submission = submit_url(
        url
    )

    if submission["status"] != "submitted":

        return submission

    analysis_id = submission.get(
        "analysis_id"
    )

    if not analysis_id:

        return {
            "status": "submitted",
            "type": "url",
            "url": url,
            "message": (
                "URL submitted, but VirusTotal "
                "did not return an analysis ID."
            )
        }

    analysis_result = wait_for_analysis(
        analysis_id
    )

    if analysis_result["status"] == "completed":

        final_report = get_url_report(
            url
        )

        if final_report["status"] == "found":

            return final_report

    if analysis_result["status"] == "rate_limited":

        return {
            "status": "rate_limited",
            "type": "url",
            "url": url,
            "analysis_id": analysis_id,
            "message": (
                "VirusTotal rate limit was reached "
                "while waiting for analysis."
            )
        }

    if analysis_result["status"] == "pending":

        return {
            "status": "pending",
            "type": "url",
            "url": url,
            "analysis_id": analysis_id,
            "message": (
                "VirusTotal analysis is still pending."
            )
        }

    return {
        "status": "submitted",
        "type": "url",
        "url": url,
        "analysis_id": analysis_id,
        "message": (
            "URL was submitted to VirusTotal, "
            "but the final report could not "
            "be retrieved."
        )
    }


# ============================================================
# File Hash Report
# ============================================================

def check_hash(file_hash):
    """Search VirusTotal using a file hash."""

    endpoint = (
        f"{BASE_URL}/files/{file_hash}"
    )

    try:

        response = requests.get(
            endpoint,
            headers=get_headers(),
            timeout=30
        )

        if response.status_code == 200:

            data = response.json()

            attributes = (
                data.get("data", {})
                .get("attributes", {})
            )

            stats = attributes.get(
                "last_analysis_stats",
                {}
            )

            return {
                "status": "found",
                "type": "file_hash",
                "hash": file_hash,
                "malicious": stats.get(
                    "malicious",
                    0
                ),
                "suspicious": stats.get(
                    "suspicious",
                    0
                ),
                "harmless": stats.get(
                    "harmless",
                    0
                ),
                "undetected": stats.get(
                    "undetected",
                    0
                )
            }

        if response.status_code == 404:

            return {
                "status": "not_found",
                "type": "file_hash",
                "hash": file_hash
            }

        if response.status_code == 429:

            return {
                "status": "rate_limited",
                "type": "file_hash",
                "hash": file_hash,
                "message": (
                    "VirusTotal API rate limit reached."
                )
            }

        return {
            "status": "error",
            "type": "file_hash",
            "hash": file_hash,
            "message": (
                f"VirusTotal returned "
                f"HTTP {response.status_code}"
            )
        }

    except requests.RequestException as error:

        return {
            "status": "error",
            "type": "file_hash",
            "hash": file_hash,
            "message": str(error)
        }