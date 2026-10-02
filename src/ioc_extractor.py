import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urlparse


# --------------------------------------------------
# Configuration
# --------------------------------------------------

# Domains that commonly appear as document/schema
# references and should not normally be treated as
# actionable phishing URLs.
IGNORED_DOMAINS = {
    "w3.org",
    "www.w3.org",
}

# File extensions that are normally document resources.
IGNORED_EXTENSIONS = {
    ".dtd",
    ".xml",
    ".xsd",
}


# --------------------------------------------------
# HTML URL extractor
# --------------------------------------------------

class HTMLLinkParser(HTMLParser):
    """Extract URLs from HTML href attributes."""

    def __init__(self):
        super().__init__()
        self.urls = []

    def handle_starttag(self, tag, attrs):
        """Process HTML start tags."""

        for attribute, value in attrs:

            if attribute.lower() != "href":
                continue

            if not value:
                continue

            value = value.strip()

            if value.startswith(
                ("http://", "https://")
            ):
                self.urls.append(value)


# --------------------------------------------------
# URL helpers
# --------------------------------------------------

def clean_url(url):
    """Remove common characters surrounding a URL."""

    if not url:
        return ""

    url = url.strip()

    # Remove HTML entities commonly found around URLs.
    url = url.replace("&amp;", "&")

    # Remove trailing punctuation.
    url = url.rstrip(
        ".,;:!?)]}>\"'"
    )

    return url


def is_valid_url(url):
    """Check whether a URL is a valid HTTP/HTTPS URL."""

    if not url:
        return False

    try:
        parsed = urlparse(url)

        if parsed.scheme.lower() not in {
            "http",
            "https"
        }:
            return False

        if not parsed.netloc:
            return False

        return True

    except Exception:
        return False


def is_ignored_url(url):
    """Identify URLs that should not be treated as actionable IOCs."""

    try:
        parsed = urlparse(url)

        domain = (
            parsed.hostname or ""
        ).lower()

        path = (
            parsed.path or ""
        ).lower()

        # Ignore W3C document/schema references.
        if domain in IGNORED_DOMAINS:
            return True

        # Ignore obvious document resources.
        for extension in IGNORED_EXTENSIONS:

            if path.endswith(extension):
                return True

        return False

    except Exception:
        return False


# --------------------------------------------------
# URL extraction
# --------------------------------------------------

def extract_urls_from_text(text):
    """Extract HTTP/HTTPS URLs from normal text."""

    if not text:
        return []

    pattern = (
        r"https?://"
        r"[^\s<>\"']+"
    )

    matches = re.findall(
        pattern,
        text,
        re.IGNORECASE
    )

    urls = []

    for match in matches:

        url = clean_url(match)

        if not url:
            continue

        if not is_valid_url(url):
            continue

        if is_ignored_url(url):
            continue

        if url not in urls:
            urls.append(url)

    return urls


def extract_urls_from_html(html_text):
    """
    Extract URLs from HTML href attributes.

    This is important for multipart email messages where
    the actual phishing link exists inside an <a href="">
    element instead of the plain-text body.
    """

    if not html_text:
        return []

    parser = HTMLLinkParser()

    try:
        parser.feed(html_text)
    except Exception:
        return []

    urls = []

    for raw_url in parser.urls:

        url = clean_url(raw_url)

        if not url:
            continue

        if not is_valid_url(url):
            continue

        if is_ignored_url(url):
            continue

        if url not in urls:
            urls.append(url)

    return urls


def extract_urls(email_body):
    """
    Extract URLs from either:

    1. A normal string
    2. A dictionary containing:
       {
           "plain_text": "...",
           "html_text": "..."
       }
    """

    if not email_body:
        return []

    urls = []

    # ----------------------------------------------
    # Dictionary body
    # ----------------------------------------------

    if isinstance(email_body, dict):

        plain_text = email_body.get(
            "plain_text",
            ""
        )

        html_text = email_body.get(
            "html_text",
            ""
        )

        text_urls = extract_urls_from_text(
            plain_text
        )

        html_urls = extract_urls_from_html(
            html_text
        )

        for url in text_urls + html_urls:

            if url not in urls:
                urls.append(url)

        return urls

    # ----------------------------------------------
    # Normal string body
    # ----------------------------------------------

    if isinstance(email_body, str):

        return extract_urls_from_text(
            email_body
        )

    return []


# --------------------------------------------------
# IP address extraction
# --------------------------------------------------

def is_valid_ip(value):
    """Check whether a value is a valid IP address."""

    try:
        ipaddress.ip_address(value)
        return True

    except ValueError:
        return False


def extract_ip_addresses(text):
    """Extract valid IPv4 addresses from text."""

    if not text:
        return []

    pattern = (
        r"\b"
        r"(?:\d{1,3}\.){3}"
        r"\d{1,3}"
        r"\b"
    )

    candidates = re.findall(
        pattern,
        text
    )

    addresses = []

    for candidate in candidates:

        if not is_valid_ip(candidate):
            continue

        if candidate not in addresses:
            addresses.append(candidate)

    return addresses


# --------------------------------------------------
# Email address extraction
# --------------------------------------------------

def extract_email_addresses(text):
    """Extract email addresses from text."""

    if not text:
        return []

    pattern = (
        r"\b"
        r"[\w.+-]+"
        r"@"
        r"[\w.-]+"
        r"\."
        r"[A-Za-z]{2,}"
        r"\b"
    )

    addresses = re.findall(
        pattern,
        text
    )

    unique_addresses = []

    for address in addresses:

        address = address.lower()

        if address not in unique_addresses:
            unique_addresses.append(address)

    return unique_addresses


# --------------------------------------------------
# Domain extraction
# --------------------------------------------------

def extract_domains(urls):
    """Extract unique domains from URLs."""

    domains = []

    for url in urls:

        try:
            parsed = urlparse(url)

            domain = (
                parsed.hostname or ""
            ).lower()

            if not domain:
                continue

            if domain not in domains:
                domains.append(domain)

        except Exception:
            continue

    return domains


# --------------------------------------------------
# Body normalization
# --------------------------------------------------

def get_searchable_text(email_body):
    """
    Combine available email body content for IP and
    email-address extraction.
    """

    if not email_body:
        return ""

    if isinstance(email_body, dict):

        plain_text = email_body.get(
            "plain_text",
            ""
        )

        html_text = email_body.get(
            "html_text",
            ""
        )

        return (
            f"{plain_text}\n"
            f"{html_text}"
        )

    if isinstance(email_body, str):
        return email_body

    return ""


# --------------------------------------------------
# Main IOC extraction function
# --------------------------------------------------

def extract_iocs(email_body):
    """
    Extract IOCs from an email body.

    Supported input:

    String:
        "Visit https://example.com"

    Dictionary:
        {
            "plain_text": "...",
            "html_text": "..."
        }

    Returns:
        {
            "urls": [],
            "domains": [],
            "ip_addresses": [],
            "email_addresses": []
        }
    """

    if not email_body:
        return {
            "urls": [],
            "domains": [],
            "ip_addresses": [],
            "email_addresses": []
        }

    # Extract URLs from both plain text and HTML.
    urls = extract_urls(
        email_body
    )

    # Extract domains from the URLs.
    domains = extract_domains(
        urls
    )

    # Build searchable content for other IOCs.
    searchable_text = get_searchable_text(
        email_body
    )

    ip_addresses = extract_ip_addresses(
        searchable_text
    )

    email_addresses = extract_email_addresses(
        searchable_text
    )

    return {
        "urls": urls,
        "domains": domains,
        "ip_addresses": ip_addresses,
        "email_addresses": email_addresses
    }