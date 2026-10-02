def correlate_evidence(
    email_details,
    header_results,
    authentication_results,
    ioc_results,
    attachment_results,
    virustotal_results,
    urlscan_results
):
    """
    Correlate evidence from the complete phishing
    investigation pipeline.

    This module organizes evidence.
    It does not calculate the final risk score.
    """

    evidence = {
        "sender": {},
        "authentication": {},
        "headers": {},
        "iocs": {},
        "attachments": {},
        "threat_intelligence": {},
        "correlations": [],
        "findings": []
    }

    # --------------------------------------------------
    # Sender
    # --------------------------------------------------

    from_header = email_details.get(
        "from",
        "Unknown"
    )

    reply_to = email_details.get(
        "reply_to",
        "Not present"
    )

    return_path = email_details.get(
        "return_path",
        "Not present"
    )

    from_domain = header_results.get(
        "from_domain",
        ""
    )

    reply_to_domain = header_results.get(
        "reply_to_domain",
        ""
    )

    return_path_domain = header_results.get(
        "return_path_domain",
        ""
    )

    evidence["sender"] = {
        "from": from_header,
        "reply_to": reply_to,
        "return_path": return_path,
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain
    }

    # --------------------------------------------------
    # Authentication
    # --------------------------------------------------

    evidence["authentication"] = {
        "spf": authentication_results.get(
            "spf",
            "unknown"
        ),
        "dkim": authentication_results.get(
            "dkim",
            "unknown"
        ),
        "dmarc": authentication_results.get(
            "dmarc",
            "unknown"
        ),
        "findings": authentication_results.get(
            "findings",
            []
        )
    }

    # --------------------------------------------------
    # Headers
    # --------------------------------------------------

    evidence["headers"] = {
        "findings": header_results.get(
            "findings",
            []
        ),
        "message_id": header_results.get(
            "message_id",
            "Not present"
        ),
        "received_headers": header_results.get(
            "received_headers",
            []
        )
    }

    # --------------------------------------------------
    # IOCs
    # --------------------------------------------------

    urls = ioc_results.get(
        "urls",
        []
    )

    domains = ioc_results.get(
        "domains",
        []
    )

    ip_addresses = ioc_results.get(
        "ip_addresses",
        []
    )

    email_addresses = ioc_results.get(
        "email_addresses",
        []
    )

    evidence["iocs"] = {
        "urls": urls,
        "domains": domains,
        "ip_addresses": ip_addresses,
        "email_addresses": email_addresses
    }

    # --------------------------------------------------
    # Attachments
    # --------------------------------------------------

    evidence["attachments"] = {
        "count": len(
            attachment_results
        ),
        "items": attachment_results
    }

    # --------------------------------------------------
    # Threat Intelligence
    # --------------------------------------------------

    evidence["threat_intelligence"] = {
        "virustotal": virustotal_results,
        "urlscan": urlscan_results
    }

    # --------------------------------------------------
    # Header correlations
    # --------------------------------------------------

    header_findings = header_results.get(
        "findings",
        []
    )

    for finding in header_findings:

        if "Display name" in finding:

            evidence["correlations"].append({
                "type": "sender_identity_mismatch",
                "description": finding,
                "severity": "high"
            })

            evidence["findings"].append(
                "Displayed sender identity does not "
                "match the actual sender domain."
            )

    # --------------------------------------------------
    # Reply-To mismatch
    # --------------------------------------------------

    if (
        from_domain
        and reply_to_domain
        and from_domain != reply_to_domain
    ):

        evidence["correlations"].append({
            "type": "reply_to_mismatch",
            "description": (
                "Reply-To domain differs from "
                "the From domain."
            ),
            "severity": "medium"
        })

        evidence["findings"].append(
            "Reply-To and From domains do not match."
        )

    # --------------------------------------------------
    # Return-Path mismatch
    # --------------------------------------------------

    if (
        from_domain
        and return_path_domain
        and from_domain != return_path_domain
    ):

        evidence["correlations"].append({
            "type": "return_path_mismatch",
            "description": (
                "Return-Path domain differs from "
                "the From domain."
            ),
            "severity": "medium"
        })

        evidence["findings"].append(
            "Return-Path and From domains do not match."
        )

    # --------------------------------------------------
    # Authentication failures
    # --------------------------------------------------

    failed_authentication = []

    if authentication_results.get("spf") == "fail":
        failed_authentication.append("SPF")

    if authentication_results.get("dkim") == "fail":
        failed_authentication.append("DKIM")

    if authentication_results.get("dmarc") == "fail":
        failed_authentication.append("DMARC")

    if failed_authentication:

        authentication_text = ", ".join(
            failed_authentication
        )

        evidence["correlations"].append({
            "type": "authentication_failure",
            "description": (
                f"Authentication failure detected: "
                f"{authentication_text}."
            ),
            "severity": "high"
        })

        evidence["findings"].append(
            "One or more email authentication "
            "mechanisms failed."
        )

    # --------------------------------------------------
    # Sender domain vs URL domain
    # --------------------------------------------------

    if urls and from_domain:

        different_domains = [
            domain
            for domain in domains
            if domain != from_domain
        ]

        if different_domains:

            evidence["correlations"].append({
                "type": "sender_url_domain_mismatch",
                "description": (
                    "Email contains URL domain(s) "
                    "different from the sender domain: "
                    + ", ".join(different_domains)
                ),
                "severity": "medium"
            })

            evidence["findings"].append(
                "Email contains a URL hosted on a "
                "different domain from the sender."
            )

    # --------------------------------------------------
    # VirusTotal URL findings
    # --------------------------------------------------

    malicious_vt_urls = 0
    suspicious_vt_urls = 0

    for result in virustotal_results:

        if result.get("status") != "found":
            continue

        malicious = result.get(
            "malicious",
            0
        )

        suspicious = result.get(
            "suspicious",
            0
        )

        if malicious > 0:
            malicious_vt_urls += 1

        elif suspicious > 0:
            suspicious_vt_urls += 1

    if malicious_vt_urls:

        evidence["correlations"].append({
            "type": "virustotal_malicious_url",
            "description": (
                f"VirusTotal reported malicious "
                f"detections for "
                f"{malicious_vt_urls} URL(s)."
            ),
            "severity": "high"
        })

        evidence["findings"].append(
            "VirusTotal identified malicious "
            "detections for one or more URLs."
        )

    elif suspicious_vt_urls:

        evidence["correlations"].append({
            "type": "virustotal_suspicious_url",
            "description": (
                f"VirusTotal reported suspicious "
                f"detections for "
                f"{suspicious_vt_urls} URL(s)."
            ),
            "severity": "medium"
        })

        evidence["findings"].append(
            "VirusTotal reported suspicious "
            "detections for one or more URLs."
        )

    # --------------------------------------------------
    # urlscan findings
    # --------------------------------------------------

    malicious_urlscan = 0

    for result in urlscan_results:

        if result.get("status") != "found":
            continue

        if result.get("malicious") is True:
            malicious_urlscan += 1

    if malicious_urlscan:

        evidence["correlations"].append({
            "type": "urlscan_malicious_url",
            "description": (
                f"urlscan reported malicious "
                f"verdicts for "
                f"{malicious_urlscan} URL(s)."
            ),
            "severity": "high"
        })

        evidence["findings"].append(
            "urlscan reported malicious behavior "
            "for one or more URLs."
        )

    # --------------------------------------------------
    # Attachment VirusTotal findings
    # --------------------------------------------------

    malicious_hashes = 0

    for result in virustotal_results:

        if result.get("type") != "file_hash":
            continue

        if result.get("status") != "found":
            continue

        if result.get("malicious", 0) > 0:
            malicious_hashes += 1

    if malicious_hashes:

        evidence["correlations"].append({
            "type": "malicious_attachment_hash",
            "description": (
                f"VirusTotal reported malicious "
                f"detections for "
                f"{malicious_hashes} attachment hash(es)."
            ),
            "severity": "high"
        })

        evidence["findings"].append(
            "One or more attachment hashes were "
            "identified as malicious."
        )

    # --------------------------------------------------
    # Summary
    # --------------------------------------------------

    evidence["summary"] = {
        "url_count": len(urls),
        "domain_count": len(domains),
        "ip_count": len(ip_addresses),
        "email_count": len(email_addresses),
        "attachment_count": len(
            attachment_results
        ),
        "correlation_count": len(
            evidence["correlations"]
        ),
        "finding_count": len(
            evidence["findings"]
        )
    }

    return evidence