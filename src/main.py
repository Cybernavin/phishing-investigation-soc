from pathlib import Path

from evidence_correlator import correlate_evidence

from email_parser import parse_email

from header_analyzer import analyze_headers

from authentication_checker import check_authentication

from ioc_extractor import extract_iocs

from attachment_analyzer import analyze_attachments

from virustotal_client import (

    check_url,

    check_hash

)

from urlscan_client import scan_url

from risk_scoring import calculate_risk

from report_generator import (
    generate_report,
    save_report
)


# Optional osTicket integration.
# The investigation still works if osticket_client.py is not configured yet.
try:
    from osticket_client import create_ticket
except ImportError:
    create_ticket = None

def choose_input():

    """Ask the user which email files to investigate."""

    print("\n==============================================")

    print("     PHISHING EMAIL INVESTIGATION TOOL")

    print("==============================================")

    print("\nHow do you want to investigate?")

    print("1. Analyze a single .eml file")

    print("2. Analyze multiple .eml files from a folder")

    while True:

        choice = input(

            "\nEnter your choice (1/2): "

        ).strip()

        if choice == "1":

            file_path = input(

                "Enter the path of the .eml file: "

            ).strip()

            file_path = Path(file_path)

            if not file_path.exists():

                print("Error: File does not exist.")

                continue

            if not file_path.is_file():

                print("Error: The path is not a file.")

                continue

            if file_path.suffix.lower() != ".eml":

                print("Error: Please provide an .eml file.")

                continue

            return [file_path]

        elif choice == "2":

            folder_path = input(

                "Enter the folder containing .eml files: "

            ).strip()

            folder_path = Path(folder_path)

            if not folder_path.exists():

                print("Error: Folder does not exist.")

                continue

            if not folder_path.is_dir():

                print("Error: The path is not a folder.")

                continue

            email_files = list(

                folder_path.glob("*.eml")

            )

            if not email_files:

                print(

                    "No .eml files were found "

                    "in this folder."

                )

                continue

            return email_files

        else:

            print(

                "Invalid choice. Please enter 1 or 2."

            )

def create_osticket_incident(
    file_path,
    email_details,
    ioc_results,
    attachment_results,
    evidence_results,
    risk_results,
    report_file
):
    """Create an osTicket incident using the completed investigation results."""

    if create_ticket is None:
        print("\n[osTicket] Integration module not available yet.")
        print("[osTicket] Investigation and report generation will continue normally.")
        return None

    subject = email_details.get("subject") or file_path.name
    severity = risk_results.get("severity", "Unknown")
    score = risk_results.get("score", 0)

    description_lines = [
        "SOC Phishing Email Investigation",
        "",
        f"Source file: {file_path.name}",
        f"Subject: {subject}",
        f"From: {email_details.get('from', 'Unknown')}",
        f"To: {email_details.get('to', 'Unknown')}",
        "",
        f"Risk Score: {score}/100",
        f"Severity: {severity}",
        "",
        "IOC Summary:",
        f"- URLs: {len(ioc_results.get('urls', []))}",
        f"- Domains: {len(ioc_results.get('domains', []))}",
        f"- IP addresses: {len(ioc_results.get('ip_addresses', []))}",
        f"- Email addresses: {len(ioc_results.get('email_addresses', []))}",
        "",
        "Evidence Correlation:",
    ]

    correlations = evidence_results.get("correlations", [])

    if correlations:
        for correlation in correlations:
            description_lines.append(
                f"- {correlation.get('description', 'No description')}"
            )
    else:
        description_lines.append("- No evidence correlations identified.")

    description_lines.extend([
        "",
        "Attachments:",
    ])

    successful_attachments = [
        attachment
        for attachment in attachment_results
        if attachment.get("status") == "success"
    ]

    if successful_attachments:
        for attachment in successful_attachments:
            description_lines.append(
                f"- {attachment.get('filename', 'Unknown')} "
                f"(SHA-256: {attachment.get('sha256', 'Unknown')})"
            )
    else:
        description_lines.append("- No successfully analyzed attachments.")

    description_lines.extend([
        "",
        f"Investigation report: {report_file}",
    ])

    title = f"Phishing Investigation - {subject}"

    try:
        ticket_result = create_ticket(
            title=title,
            description="\n".join(description_lines),
            severity=severity,
            risk_score=score,
            source_file=file_path.name
        )

        if ticket_result:
            print("\n[osTicket] Incident ticket created successfully.")
            print(
                f"[osTicket] Ticket: "
                f"{ticket_result.get('ticket_number', 'Unknown')}"
            )
        else:
            print("\n[osTicket] Ticket creation returned no result.")

        return ticket_result

    except Exception as error:
        print("\n[osTicket] Ticket creation failed.")
        print(f"[osTicket] {error}")
        return None


def investigate_email(file_path):

    """Run the complete investigation on one email."""

    print("\n" + "=" * 70)

    print(

        f"Analyzing: {file_path.name}"

    )

    print("=" * 70)

    # --------------------------------------------------

    # 1. PARSE EMAIL

    # --------------------------------------------------

    print("\n[1] Parsing email...")

    email_data = parse_email(

        file_path

    )

    email_message = email_data["message"]

    email_details = email_data["details"]

    email_body = email_data["body"]

    attachment_files = email_data["attachments"]

    print(

        "Email parsed successfully."

    )

    # --------------------------------------------------

    # 2. HEADER ANALYSIS

    # --------------------------------------------------

    print("\n[2] Analyzing email headers...")

    header_results = analyze_headers(

        email_message

    )

    print(

        "Header analysis completed."

    )

    # --------------------------------------------------

    # 3. AUTHENTICATION CHECK

    # --------------------------------------------------

    print(

        "\n[3] Checking SPF, DKIM and DMARC..."

    )

    authentication_results = check_authentication(

        email_message

    )

    print(

        "Authentication check completed."

    )

    # --------------------------------------------------

    # 4. IOC EXTRACTION

    # --------------------------------------------------

    print("\n[4] Extracting IOCs...")

    ioc_results = extract_iocs(

        email_body

    )

    print(

        f"URLs found    : "

        f"{len(ioc_results['urls'])}"

    )

    print(

        f"Domains found : "

        f"{len(ioc_results['domains'])}"

    )

    print(

        f"IP addresses  : "

        f"{len(ioc_results['ip_addresses'])}"

    )

    print(

        f"Email addresses: "

        f"{len(ioc_results['email_addresses'])}"

    )

    # --------------------------------------------------

    # 5. ATTACHMENT ANALYSIS

    # --------------------------------------------------

    print("\n[5] Analyzing attachments...")

    attachment_results = analyze_attachments(

        attachment_files

    )

    if attachment_results:

        print(

            f"Attachments analyzed: "

            f"{len(attachment_results)}"

        )

        for attachment in attachment_results:

            if attachment.get("status") == "success":

                print(

                    f"- {attachment['filename']}"

                )

                print(

                    f"  SHA-256: "

                    f"{attachment['sha256']}"

                )

            else:

                print(

                    f"- Attachment analysis failed: "

                    f"{attachment.get('message')}"

                )

    else:

        print(

            "No attachments found."

        )

    # --------------------------------------------------

    # 6. THREAT INTELLIGENCE

    # --------------------------------------------------

    print(

        "\n[6] Threat intelligence analysis..."

    )

    virustotal_results = []

    urlscan_results = []

    urls = ioc_results.get(

        "urls",

        []

    )

    # --------------------------------------------------

    # URL Threat Intelligence

    # --------------------------------------------------

    if urls:

        for number, url in enumerate(

            urls,

            start=1

        ):

            print(

                f"\nURL {number}/{len(urls)}"

            )

            print(url)

            # ------------------------------------------

            # VirusTotal

            # ------------------------------------------

            print(

                "  VirusTotal: checking..."

            )

            try:

                vt_result = check_url(

                    url

                )

            except Exception as error:

                vt_result = {

                    "status": "error",

                    "type": "url",

                    "url": url,

                    "message": str(error)

                }

            virustotal_results.append(

                vt_result

            )

            print(

                f"  VirusTotal: "

                f"{vt_result.get('status', 'unknown')}"

            )

            if vt_result.get("message"):

                print(

                    f"    {vt_result['message']}"

                )

            # ------------------------------------------

            # urlscan.io

            # ------------------------------------------

            print(

                "  urlscan.io: checking..."

            )

            try:

                urlscan_result = scan_url(

                    url

                )

            except Exception as error:

                urlscan_result = {

                    "status": "error",

                    "type": "url",

                    "url": url,

                    "message": str(error)

                }

            urlscan_results.append(

                urlscan_result

            )

            print(

                f"  urlscan.io: "

                f"{urlscan_result.get('status', 'unknown')}"

            )

            if urlscan_result.get("message"):

                print(

                    f"    {urlscan_result['message']}"

                )

    else:

        print(

            "No URLs found."

        )

    # --------------------------------------------------

    # Attachment Hash Threat Intelligence

    # --------------------------------------------------

    successful_attachments = [

        attachment

        for attachment in attachment_results

        if attachment.get("status") == "success"

    ]

    if successful_attachments:

        print(

            "\nAttachment hash reputation checks..."

        )

        for number, attachment in enumerate(

            successful_attachments,

            start=1

        ):

            sha256 = attachment.get(

                "sha256"

            )

            if not sha256:

                continue

            print(

                f"\nAttachment {number}/"

                f"{len(successful_attachments)}"

            )

            print(

                f"  File: "

                f"{attachment.get('filename')}"

            )

            print(

                f"  SHA-256: {sha256}"

            )

            print(

                "  VirusTotal: checking..."

            )

            try:

                hash_result = check_hash(

                    sha256

                )

            except Exception as error:

                hash_result = {

                    "status": "error",

                    "type": "file_hash",

                    "hash": sha256,

                    "message": str(error)

                }

            virustotal_results.append(

                hash_result

            )

            print(

                f"  VirusTotal: "

                f"{hash_result.get('status', 'unknown')}"

            )

            if hash_result.get("message"):

                print(

                    f"    {hash_result['message']}"

                )

    # --------------------------------------------------

    # 7. EVIDENCE CORRELATION

    # --------------------------------------------------

    print(

        "\n[7] Correlating investigation evidence..."

    )

    evidence_results = correlate_evidence(

        email_details,

        header_results,

        authentication_results,

        ioc_results,

        attachment_results,

        virustotal_results,

        urlscan_results

    )

    print(

        f"Evidence correlations: "

        f"{evidence_results['summary']['correlation_count']}"

    )

    print(

        f"Investigation findings: "

        f"{evidence_results['summary']['finding_count']}"

    )

    if evidence_results.get("correlations"):

        print("\nCorrelations:")

        for correlation in evidence_results[

            "correlations"

        ]:

            print(

                f"- {correlation.get('description')}"

            )

    # --------------------------------------------------

    # 8. RISK SCORING

    # --------------------------------------------------

    print(

        "\n[8] Calculating risk score..."

    )

    risk_results = calculate_risk(

        evidence_results

    )

    print(

        f"Risk Score : "

        f"{risk_results['score']}/100"

    )

    print(

        f"Severity   : "

        f"{risk_results['severity']}"

    )

    # --------------------------------------------------

    # 9. DISPLAY SUMMARY

    # --------------------------------------------------

    show_summary(

        file_path,

        email_details,

        header_results,

        authentication_results,

        ioc_results,

        attachment_results,

        virustotal_results,

        urlscan_results,

        evidence_results,

        risk_results

    )

    # --------------------------------------------------

    # 10. GENERATE REPORT

    # --------------------------------------------------

    print(

        "\n[10] Generating investigation report..."

    )

    report = generate_report(
        file_path.name,
        email_details,
        header_results,
        authentication_results,
        ioc_results,
        attachment_results,
        virustotal_results,
        urlscan_results,
        evidence_results,
        risk_results
    )

    report_file = save_report(

        report

    )

    print(

        f"\nReport saved to:\n"

        f"{report_file}"

    )

    # --------------------------------------------------
    # 11. osTICKET INTEGRATION
    # --------------------------------------------------

    print("\n[11] Creating osTicket incident...")

    osticket_result = create_osticket_incident(
        file_path,
        email_details,
        ioc_results,
        attachment_results,
        evidence_results,
        risk_results,
        report_file
    )

    return {

        "email_details": email_details,

        "header_results": header_results,

        "authentication_results": authentication_results,

        "ioc_results": ioc_results,

        "attachment_results": attachment_results,

        "virustotal_results": virustotal_results,

        "urlscan_results": urlscan_results,

        "evidence_results": evidence_results,

        "risk_results": risk_results,

        "report_file": report_file,

        "osticket_result": osticket_result

    }

def show_summary(

    file_path,

    email_details,

    header_results,

    authentication_results,

    ioc_results,

    attachment_results,

    virustotal_results,

    urlscan_results,

    evidence_results,

    risk_results

):

    """Display a readable investigation summary."""

    print("\n")

    print("=" * 70)

    print("              INVESTIGATION SUMMARY")

    print("=" * 70)

    # ======================================================

    # Email

    # ======================================================

    print("\n[EMAIL]")

    print(

        f"File    : {file_path.name}"

    )

    print(

        f"From    : "

        f"{email_details.get('from', 'Unknown')}"

    )

    print(

        f"To      : "

        f"{email_details.get('to', 'Unknown')}"

    )

    print(

        f"Subject : "

        f"{email_details.get('subject', 'Unknown')}"

    )

    # ======================================================

    # Headers

    # ======================================================

    print("\n[HEADER ANALYSIS]")

    if header_results.get("findings"):

        for finding in header_results[

            "findings"

        ]:

            print(

                f"- {finding}"

            )

    else:

        print(

            "- No obvious header anomalies found."

        )

    # ======================================================

    # Authentication

    # ======================================================

    print("\n[AUTHENTICATION]")

    print(

        f"SPF   : "

        f"{authentication_results.get('spf', 'unknown')}"

    )

    print(

        f"DKIM  : "

        f"{authentication_results.get('dkim', 'unknown')}"

    )

    print(

        f"DMARC : "

        f"{authentication_results.get('dmarc', 'unknown')}"

    )

    # ======================================================

    # IOCs

    # ======================================================

    print("\n[IOCs]")

    print(

        f"URLs           : "

        f"{len(ioc_results.get('urls', []))}"

    )

    print(

        f"Domains        : "

        f"{len(ioc_results.get('domains', []))}"

    )

    print(

        f"IP addresses   : "

        f"{len(ioc_results.get('ip_addresses', []))}"

    )

    print(

        f"Email addresses: "

        f"{len(ioc_results.get('email_addresses', []))}"

    )

    if ioc_results.get("urls"):

        print("\nURLs:")

        for url in ioc_results["urls"]:

            print(

                f"- {url}"

            )

    # ======================================================

    # Attachments

    # ======================================================

    print("\n[ATTACHMENTS]")

    if attachment_results:

        for attachment in attachment_results:

            if attachment.get("status") == "success":

                print(

                    f"- {attachment['filename']}"

                )

                print(

                    f"  SHA-256: "

                    f"{attachment['sha256']}"

                )

            else:

                print(

                    f"- "

                    f"{attachment.get('message')}"

                )

    else:

        print(

            "- No attachments found."

        )

    # ======================================================

    # Threat Intelligence

    # ======================================================

    print("\n[THREAT INTELLIGENCE]")

    print(

        f"VirusTotal checks: "

        f"{len(virustotal_results)}"

    )

    print(

        f"urlscan.io checks: "

        f"{len(urlscan_results)}"

    )

    # ======================================================

    # Evidence Correlation

    # ======================================================

    print("\n[EVIDENCE CORRELATION]")

    print(

        f"Correlations: "

        f"{evidence_results['summary']['correlation_count']}"

    )

    print(

        f"Findings: "

        f"{evidence_results['summary']['finding_count']}"

    )

    if evidence_results.get("correlations"):

        for correlation in evidence_results[

            "correlations"

        ]:

            print(

                f"- "

                f"{correlation.get('description')}"

            )

    # ======================================================

    # Risk

    # ======================================================

    print("\n[RISK ASSESSMENT]")

    print(

        f"Score    : "

        f"{risk_results['score']}/100"

    )

    print(

        f"Severity : "

        f"{risk_results['severity']}"

    )

    print("\nReasons:")

    if risk_results.get("reasons"):

        for reason in risk_results[

            "reasons"

        ]:

            print(

                f"- {reason}"

            )

    else:

        print(

            "- No risk factors identified."

        )

    print("=" * 70)

def main():

    email_files = choose_input()

    print(

        f"\nFound {len(email_files)} "

        f"email file(s) to investigate."

    )

    successful = 0

    failed = 0

    for number, file_path in enumerate(

        email_files,

        start=1

    ):

        print(

            f"\n\nEmail {number}/"

            f"{len(email_files)}"

        )

        try:

            result = investigate_email(

                file_path

            )

            if result:

                successful += 1

        except Exception as error:

            failed += 1

            print(

                f"\nInvestigation failed "

                f"for {file_path.name}:"

            )

            print(error)

    print("\n")

    print("=" * 70)

    print("              INVESTIGATION COMPLETE")

    print("=" * 70)

    print(

        f"Successful : {successful}"

    )

    print(

        f"Failed     : {failed}"

    )

    print("=" * 70)

if __name__ == "__main__":

    main()