import re
from email.message import EmailMessage


def get_authentication_results(
    email_message: EmailMessage
):
    """Get all Authentication-Results headers."""

    return email_message.get_all(
        "Authentication-Results",
        []
    )


def get_received_spf_results(
    email_message: EmailMessage
):
    """Get all Received-SPF headers."""

    return email_message.get_all(
        "Received-SPF",
        []
    )


def extract_authentication_result(
    header_text,
    authentication_type
):
    """Extract an SPF, DKIM or DMARC result from a header."""

    pattern = (
        rf"\b{authentication_type}"
        rf"\s*=\s*"
        rf"([a-zA-Z]+)"
    )

    match = re.search(
        pattern,
        header_text,
        re.IGNORECASE
    )

    if match:
        return match.group(1).lower()

    return None


def check_authentication(
    email_message: EmailMessage
):
    """
    Check SPF, DKIM and DMARC authentication results.

    The function reads authentication information that is
    already present in the email headers. It does not perform
    a live SPF, DKIM or DMARC DNS check.
    """

    authentication_headers = (
        get_authentication_results(
            email_message
        )
    )

    received_spf_headers = (
        get_received_spf_results(
            email_message
        )
    )

    result = {
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
        "raw": authentication_headers,
        "received_spf": received_spf_headers,
        "findings": []
    }

    # --------------------------------------------------
    # Authentication-Results
    # --------------------------------------------------

    if authentication_headers:

        auth_text = " ".join(
            authentication_headers
        )

        spf_result = extract_authentication_result(
            auth_text,
            "spf"
        )

        dkim_result = extract_authentication_result(
            auth_text,
            "dkim"
        )

        dmarc_result = extract_authentication_result(
            auth_text,
            "dmarc"
        )

        if spf_result:
            result["spf"] = spf_result

        if dkim_result:
            result["dkim"] = dkim_result

        if dmarc_result:
            result["dmarc"] = dmarc_result

    # --------------------------------------------------
    # Received-SPF fallback
    # --------------------------------------------------

    if (
        result["spf"] == "unknown"
        and received_spf_headers
    ):

        received_spf_text = " ".join(
            received_spf_headers
        )

        spf_match = re.search(
            r"^\s*(pass|fail|softfail|neutral|"
            r"none|temperror|permerror)\b",
            received_spf_text,
            re.IGNORECASE
        )

        if spf_match:
            result["spf"] = (
                spf_match.group(1).lower()
            )

    # --------------------------------------------------
    # SPF findings
    # --------------------------------------------------

    if result["spf"] == "fail":

        result["findings"].append(
            "SPF authentication failed."
        )

    elif result["spf"] == "softfail":

        result["findings"].append(
            "SPF authentication returned softfail."
        )

    elif result["spf"] == "permerror":

        result["findings"].append(
            "SPF authentication returned a permanent error."
        )

    elif result["spf"] == "temperror":

        result["findings"].append(
            "SPF authentication returned a temporary error."
        )

    # --------------------------------------------------
    # DKIM findings
    # --------------------------------------------------

    if result["dkim"] == "fail":

        result["findings"].append(
            "DKIM authentication failed."
        )

    elif result["dkim"] == "temperror":

        result["findings"].append(
            "DKIM authentication returned a temporary error."
        )

    elif result["dkim"] == "permerror":

        result["findings"].append(
            "DKIM authentication returned a permanent error."
        )

    # --------------------------------------------------
    # DMARC findings
    # --------------------------------------------------

    if result["dmarc"] == "fail":

        result["findings"].append(
            "DMARC authentication failed."
        )

    elif result["dmarc"] == "temperror":

        result["findings"].append(
            "DMARC authentication returned a temporary error."
        )

    elif result["dmarc"] == "permerror":

        result["findings"].append(
            "DMARC authentication returned a permanent error."
        )

    # --------------------------------------------------
    # Missing authentication information
    # --------------------------------------------------

    if not authentication_headers:

        if not received_spf_headers:

            result["findings"].append(
                "No SPF, DKIM or DMARC authentication "
                "results were found in the email headers."
            )

        else:

            result["findings"].append(
                "Authentication-Results header was not found. "
                "SPF information was obtained from Received-SPF."
            )

    # --------------------------------------------------
    # Individual unknown results
    # --------------------------------------------------

    if (
        authentication_headers
        and result["spf"] == "unknown"
    ):

        result["findings"].append(
            "SPF result was not present in "
            "the Authentication-Results header."
        )

    if (
        authentication_headers
        and result["dkim"] == "unknown"
    ):

        result["findings"].append(
            "DKIM result was not present in "
            "the Authentication-Results header."
        )

    if (
        authentication_headers
        and result["dmarc"] == "unknown"
    ):

        result["findings"].append(
            "DMARC result was not present in "
            "the Authentication-Results header."
        )

    return result