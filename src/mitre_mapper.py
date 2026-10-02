# ============================================================
# MITRE ATT&CK MAPPER
# ============================================================
#
# This module maps investigation evidence to relevant
# MITRE ATT&CK techniques.
#
# Important:
# The mapper only creates a technique mapping when there is
# supporting evidence.
#
# It does not assume that every URL or attachment is malicious.
# ============================================================


MITRE_TECHNIQUES = {

    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access"
    },

    "T1566.001": {
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access"
    },

    "T1566.002": {
        "name": "Spearphishing Link",
        "tactic": "Initial Access"
    },

    "T1204.001": {
        "name": "User Execution: Malicious Link",
        "tactic": "Execution"
    },

    "T1204.002": {
        "name": "User Execution: Malicious File",
        "tactic": "Execution"
    }
}


def create_mapping(
    technique_id,
    evidence,
    confidence="medium"
):
    """
    Create one MITRE ATT&CK technique mapping.
    """

    technique = MITRE_TECHNIQUES.get(
        technique_id
    )

    if not technique:
        return None

    return {
        "technique_id": technique_id,
        "technique": technique["name"],
        "tactic": technique["tactic"],
        "confidence": confidence,
        "evidence": evidence
    }


def has_correlation(
    correlations,
    correlation_type
):
    """
    Check whether a specific evidence correlation exists.
    """

    for correlation in correlations:

        if correlation.get("type") == correlation_type:
            return True

    return False


def get_correlation_evidence(
    correlations,
    correlation_type
):
    """
    Return descriptions for a specific correlation type.
    """

    evidence = []

    for correlation in correlations:

        if correlation.get("type") != correlation_type:
            continue

        description = correlation.get(
            "description"
        )

        if description:
            evidence.append(
                description
            )

    return evidence


def map_phishing_techniques(
    evidence,
    mappings
):
    """
    Map phishing-related evidence.
    """

    iocs = evidence.get(
        "iocs",
        {}
    )

    urls = iocs.get(
        "urls",
        []
    )

    attachments = evidence.get(
        "attachments",
        {}
    )

    attachment_count = attachments.get(
        "count",
        0
    )

    correlations = evidence.get(
        "correlations",
        []
    )

    threat_intelligence = evidence.get(
        "threat_intelligence",
        {}
    )

    virustotal_results = threat_intelligence.get(
        "virustotal",
        []
    )

    urlscan_results = threat_intelligence.get(
        "urlscan",
        []
    )

    # ========================================================
    # Spearphishing Link
    # T1566.002
    # ========================================================

    malicious_url = has_correlation(
        correlations,
        "malicious_url_reputation"
    )

    suspicious_url = has_correlation(
        correlations,
        "suspicious_url_reputation"
    )

    urlscan_malicious = has_correlation(
        correlations,
        "urlscan_malicious"
    )

    if (
        urls
        and (
            malicious_url
            or suspicious_url
            or urlscan_malicious
        )
    ):

        evidence_items = []

        evidence_items.extend(
            get_correlation_evidence(
                correlations,
                "malicious_url_reputation"
            )
        )

        evidence_items.extend(
            get_correlation_evidence(
                correlations,
                "suspicious_url_reputation"
            )
        )

        evidence_items.extend(
            get_correlation_evidence(
                correlations,
                "urlscan_malicious"
            )
        )

        mappings.append(
            create_mapping(
                "T1566.002",
                evidence_items,
                "high"
            )
        )

    # ========================================================
    # Spearphishing Attachment
    # T1566.001
    # ========================================================

    malicious_attachment = has_correlation(
        correlations,
        "attachment_threat_intelligence"
    )

    if (
        attachment_count > 0
        and malicious_attachment
    ):

        evidence_items = (
            get_correlation_evidence(
                correlations,
                "attachment_threat_intelligence"
            )
        )

        mappings.append(
            create_mapping(
                "T1566.001",
                evidence_items,
                "high"
            )
        )


def map_user_execution(
    evidence,
    mappings
):
    """
    Map User Execution techniques only when the available
    evidence supports malicious user interaction.

    The email containing a normal URL or attachment is not
    enough to prove User Execution.
    """

    correlations = evidence.get(
        "correlations",
        []
    )

    # ========================================================
    # T1204.001 - Malicious Link
    # ========================================================

    malicious_link_evidence = []

    for correlation_type in [
        "malicious_url_reputation",
        "urlscan_malicious"
    ]:

        malicious_link_evidence.extend(
            get_correlation_evidence(
                correlations,
                correlation_type
            )
        )

    if malicious_link_evidence:

        mappings.append(
            create_mapping(
                "T1204.001",
                malicious_link_evidence,
                "medium"
            )
        )

    # ========================================================
    # T1204.002 - Malicious File
    # ========================================================

    malicious_file_evidence = (
        get_correlation_evidence(
            correlations,
            "attachment_threat_intelligence"
        )
    )

    if malicious_file_evidence:

        mappings.append(
            create_mapping(
                "T1204.002",
                malicious_file_evidence,
                "medium"
            )
        )


def map_sender_spoofing(
    evidence,
    mappings
):
    """
    Analyze sender-related evidence.

    At this stage we keep the evidence as supporting context
    rather than assigning an unsupported ATT&CK technique.

    Examples:

        - display-name mismatch
        - Reply-To mismatch
        - Return-Path mismatch
        - authentication failures
    """

    correlations = evidence.get(
        "correlations",
        []
    )

    spoofing_evidence = []

    for correlation_type in [
        "sender_identity_mismatch",
        "reply_to_mismatch",
        "return_path_mismatch",
        "authentication_failure"
    ]:

        spoofing_evidence.extend(
            get_correlation_evidence(
                correlations,
                correlation_type
            )
        )

    return spoofing_evidence


def remove_duplicate_mappings(
    mappings
):
    """
    Prevent duplicate MITRE technique mappings.
    """

    unique_mappings = []

    seen = set()

    for mapping in mappings:

        if not mapping:
            continue

        technique_id = mapping.get(
            "technique_id"
        )

        if technique_id in seen:
            continue

        seen.add(
            technique_id
        )

        unique_mappings.append(
            mapping
        )

    return unique_mappings


def map_to_mitre(evidence):
    """
    Map investigation evidence to MITRE ATT&CK.

    Input:
        Evidence dictionary from evidence_correlator.py.

    Output:
        {
            "mappings": [],
            "count": 0
        }
    """

    mappings = []

    map_phishing_techniques(
        evidence,
        mappings
    )

    map_user_execution(
        evidence,
        mappings
    )

    mappings = remove_duplicate_mappings(
        mappings
    )

    return {
        "mappings": mappings,
        "count": len(mappings)
    }