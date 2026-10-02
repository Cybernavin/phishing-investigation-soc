"""
Risk scoring for the phishing email investigation pipeline.

This module receives the evidence_results object produced by
evidence_correlator.py.

The function signature is intentionally kept simple:

    calculate_risk(evidence_results)

This matches the current main.py pipeline.
"""


def calculate_risk(evidence_results):
    """
    Calculate the phishing risk score from correlated evidence.

    Score range:
        0 - 100

    Severity:
        0-39   -> Low
        40-69  -> Medium
        70-100 -> High

    The score is based on investigation evidence rather than
    simply counting the number of URLs in the email.
    """

    if not isinstance(evidence_results, dict):
        return {
            "score": 0,
            "severity": "Low",
            "reasons": [
                "No valid evidence results were provided."
            ]
        }

    correlations = evidence_results.get(
        "correlations",
        []
    )

    score = 0
    reasons = []

    # --------------------------------------------------
    # Count important evidence
    # --------------------------------------------------

    vt_malicious_urls = 0
    vt_suspicious_urls = 0
    urlscan_malicious = 0
    urlscan_redirects = 0

    spf_fail = False
    dkim_fail = False
    dmarc_fail = False

    sender_url_mismatch = False
    reply_to_mismatch = False
    return_path_mismatch = False

    malicious_attachment = False
    suspicious_attachment = False

    # --------------------------------------------------
    # Read evidence correlations
    # --------------------------------------------------

    for correlation in correlations:

        if isinstance(correlation, dict):
            description = str(
                correlation.get(
                    "description",
                    ""
                )
            ).lower()

        else:
            description = str(
                correlation
            ).lower()

        # ----------------------------------------------
        # Authentication
        # ----------------------------------------------

        if "spf" in description and "fail" in description:
            spf_fail = True

        if "dkim" in description and "fail" in description:
            dkim_fail = True

        if "dmarc" in description and "fail" in description:
            dmarc_fail = True

        # ----------------------------------------------
        # Header / identity mismatch
        # ----------------------------------------------

        if (
            "reply-to" in description
            and "from" in description
            and (
                "differ" in description
                or "mismatch" in description
            )
        ):
            reply_to_mismatch = True

        if (
            "return-path" in description
            and "from" in description
            and (
                "differ" in description
                or "mismatch" in description
            )
        ):
            return_path_mismatch = True

        # ----------------------------------------------
        # Sender / URL domain mismatch
        # ----------------------------------------------

        if (
            "url domain" in description
            and (
                "different" in description
                or "differs" in description
            )
        ):
            sender_url_mismatch = True

        # ----------------------------------------------
        # VirusTotal malicious URLs
        # ----------------------------------------------

        if "virustotal" in description:

            if (
                "malicious detections for" in description
                and "url" in description
            ):
                number = _extract_number(
                    description
                )

                if number is not None:
                    vt_malicious_urls += number
                else:
                    vt_malicious_urls += 1

            elif (
                "malicious detection" in description
            ):
                vt_malicious_urls += 1

            elif (
                "suspicious" in description
            ):
                number = _extract_number(
                    description
                )

                if number is not None:
                    vt_suspicious_urls += number
                else:
                    vt_suspicious_urls += 1

        # ----------------------------------------------
        # urlscan malicious verdict
        # ----------------------------------------------

        if "urlscan" in description:

            if (
                "malicious verdict" in description
                or "malicious verdicts" in description
            ):
                number = _extract_number(
                    description
                )

                if number is not None:
                    urlscan_malicious += number
                else:
                    urlscan_malicious += 1

            # ------------------------------------------
            # Redirect evidence
            # ------------------------------------------

            if "redirect" in description:
                number = _extract_number(
                    description
                )

                if number is not None:
                    urlscan_redirects += number
                else:
                    urlscan_redirects += 1

        # ----------------------------------------------
        # Attachment evidence
        # ----------------------------------------------

        if "malicious attachment" in description:
            malicious_attachment = True

        if "suspicious attachment" in description:
            suspicious_attachment = True

    # --------------------------------------------------
    # Authentication scoring
    # --------------------------------------------------

    if spf_fail:
        score += 10
        reasons.append(
            "SPF authentication failed."
        )

    if dkim_fail:
        score += 10
        reasons.append(
            "DKIM authentication failed."
        )

    if dmarc_fail:
        score += 15
        reasons.append(
            "DMARC authentication failed."
        )

    # --------------------------------------------------
    # Header / identity scoring
    # --------------------------------------------------

    if reply_to_mismatch:
        score += 10
        reasons.append(
            "Reply-To and From domains do not match."
        )

    if return_path_mismatch:
        score += 10
        reasons.append(
            "Return-Path and From domains do not match."
        )

    if sender_url_mismatch:
        score += 10
        reasons.append(
            "A URL domain differs from the sender domain."
        )

    # --------------------------------------------------
    # VirusTotal scoring
    # --------------------------------------------------

    if vt_malicious_urls > 0:

        points = vt_malicious_urls * 25

        score += points

        reasons.append(
            f"VirusTotal reported "
            f"{vt_malicious_urls} malicious URL(s). "
            f"+{points} points."
        )

    if vt_suspicious_urls > 0:

        points = vt_suspicious_urls * 10

        score += points

        reasons.append(
            f"VirusTotal reported "
            f"{vt_suspicious_urls} suspicious URL(s). "
            f"+{points} points."
        )

    # --------------------------------------------------
    # urlscan scoring
    # --------------------------------------------------

    if urlscan_malicious > 0:

        # urlscan is treated as corroborating evidence.
        # It does not receive the same full weight as a
        # separate malicious URL from VirusTotal.

        points = urlscan_malicious * 15

        score += points

        reasons.append(
            f"urlscan reported malicious verdicts "
            f"for {urlscan_malicious} URL(s). "
            f"+{points} points."
        )

    # --------------------------------------------------
    # Redirect scoring
    # --------------------------------------------------

    if urlscan_redirects > 0:

        points = min(
            urlscan_redirects * 5,
            10
        )

        score += points

        reasons.append(
            f"{urlscan_redirects} URL(s) redirected "
            f"during urlscan analysis. "
            f"+{points} points."
        )

    # --------------------------------------------------
    # Attachment scoring
    # --------------------------------------------------

    if malicious_attachment:

        score += 35

        reasons.append(
            "A malicious attachment was identified. "
            "+35 points."
        )

    elif suspicious_attachment:

        score += 15

        reasons.append(
            "A suspicious attachment was identified. "
            "+15 points."
        )

    # --------------------------------------------------
    # Keep score inside 0-100
    # --------------------------------------------------

    score = min(
        max(score, 0),
        100
    )

    # --------------------------------------------------
    # Severity
    # --------------------------------------------------

    if score >= 70:
        severity = "High"

    elif score >= 40:
        severity = "Medium"

    else:
        severity = "Low"

    # --------------------------------------------------
    # Return result
    # --------------------------------------------------

    return {
        "score": score,
        "severity": severity,
        "reasons": reasons
    }


def _extract_number(text):
    """
    Extract the first integer from a text string.

    Example:

        'VirusTotal reported malicious detections for 2 URL(s).'

    returns:

        2
    """

    number = ""

    for character in text:

        if character.isdigit():
            number += character

        elif number:
            break

    if number:
        return int(number)

    return None