import re
from email.message import EmailMessage
from email.utils import parseaddr


def get_header(email_message: EmailMessage, name: str):
    """Get a single email header."""

    return email_message.get(name, "").strip()


def extract_domain(email_address: str):
    """Extract the domain from an email address."""

    if not email_address:
        return ""

    address = parseaddr(email_address)[1]

    if "@" not in address:
        return ""

    return address.split("@", 1)[1].lower()


def extract_email(email_header: str):
    """Extract the email address from a header."""

    if not email_header:
        return ""

    return parseaddr(email_header)[1].lower()


def extract_display_name(email_header: str):
    """Extract the display name from a From header."""

    if not email_header:
        return ""

    return parseaddr(email_header)[0].strip()


def analyze_display_name(
    from_header: str,
    findings: list
):
    """Check for suspicious display-name and domain mismatch."""

    display_name = extract_display_name(
        from_header
    )

    sender_email = extract_email(
        from_header
    )

    sender_domain = extract_domain(
        from_header
    )

    if not display_name or not sender_email:
        return

    display_domain_match = re.search(
        r"(?i)(?:^|\s)(?:https?://)?"
        r"(?:www\.)?"
        r"([a-z0-9.-]+\.[a-z]{2,})"
        r"(?:\s|$)",
        display_name
    )

    if not display_domain_match:
        return

    displayed_domain = (
        display_domain_match.group(1).lower()
    )

    if displayed_domain != sender_domain:
        findings.append(
            "Display name contains a domain that "
            "does not match the actual sender domain: "
            f"{displayed_domain} vs {sender_domain}."
        )


def analyze_reply_to(
    from_header: str,
    reply_to_header: str,
    findings: list
):
    """Check for a From and Reply-To domain mismatch."""

    if not reply_to_header:
        return

    from_domain = extract_domain(
        from_header
    )

    reply_domain = extract_domain(
        reply_to_header
    )

    if (
        from_domain
        and reply_domain
        and from_domain != reply_domain
    ):
        findings.append(
            "Reply-To domain does not match "
            "the From domain: "
            f"{reply_domain} vs {from_domain}."
        )


def analyze_return_path(
    from_header: str,
    return_path_header: str,
    findings: list
):
    """Check for a From and Return-Path domain mismatch."""

    if not return_path_header:
        return

    from_domain = extract_domain(
        from_header
    )

    return_domain = extract_domain(
        return_path_header
    )

    if (
        from_domain
        and return_domain
        and from_domain != return_domain
    ):
        findings.append(
            "Return-Path domain does not match "
            "the From domain: "
            f"{return_domain} vs {from_domain}."
        )


def analyze_received_headers(
    received_headers,
    findings: list
):
    """Analyze Received headers for basic anomalies."""

    if not received_headers:
        findings.append(
            "No Received headers were found."
        )
        return

    if len(received_headers) > 10:
        findings.append(
            f"Email contains an unusually large number "
            f"of Received headers: {len(received_headers)}."
        )

    for received in received_headers:

        received_lower = received.lower()

        if "unknown" in received_lower:
            findings.append(
                "A Received header contains "
                "an unknown host."
            )

        if "localhost" in received_lower:
            findings.append(
                "A Received header references localhost."
            )


def analyze_message_id(
    message_id: str,
    findings: list
):
    """Perform basic Message-ID validation."""

    if not message_id:
        findings.append(
            "Message-ID header is missing."
        )
        return

    if "@" not in message_id:
        findings.append(
            "Message-ID does not contain "
            "a normal domain component."
        )


def analyze_headers(
    email_message: EmailMessage
):
    """
    Analyze important email headers.

    Returns a dictionary containing the headers,
    extracted domains and analyst findings.
    """

    from_header = get_header(
        email_message,
        "From"
    )

    to_header = get_header(
        email_message,
        "To"
    )

    subject = get_header(
        email_message,
        "Subject"
    )

    reply_to = get_header(
        email_message,
        "Reply-To"
    )

    return_path = get_header(
        email_message,
        "Return-Path"
    )

    message_id = get_header(
        email_message,
        "Message-ID"
    )

    received_headers = email_message.get_all(
        "Received",
        []
    )

    findings = []

    analyze_display_name(
        from_header,
        findings
    )

    analyze_reply_to(
        from_header,
        reply_to,
        findings
    )

    analyze_return_path(
        from_header,
        return_path,
        findings
    )

    analyze_received_headers(
        received_headers,
        findings
    )

    analyze_message_id(
        message_id,
        findings
    )

    return {
        "from": from_header,
        "to": to_header,
        "subject": subject,
        "reply_to": reply_to,
        "return_path": return_path,
        "message_id": message_id,
        "received_headers": received_headers,
        "from_domain": extract_domain(
            from_header
        ),
        "reply_to_domain": extract_domain(
            reply_to
        ),
        "return_path_domain": extract_domain(
            return_path
        ),
        "findings": findings
    }