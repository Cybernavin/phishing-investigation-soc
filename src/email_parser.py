from email.message import EmailMessage
from email import policy
from email.parser import BytesParser
from pathlib import Path


def load_email(file_path):
    """Read and parse an .eml file."""

    with open(file_path, "rb") as file:
        email_message = BytesParser(
            policy=policy.default
        ).parse(file)

    return email_message


def get_email_details(email_message: EmailMessage):
    """Get basic information from the email."""

    details = {
        "from": email_message.get(
            "From",
            "Unknown"
        ),

        "to": email_message.get(
            "To",
            "Unknown"
        ),

        "subject": email_message.get(
            "Subject",
            "No Subject"
        ),

        "date": email_message.get(
            "Date",
            "Unknown"
        ),

        "reply_to": email_message.get(
            "Reply-To",
            "Not present"
        ),

        "return_path": email_message.get(
            "Return-Path",
            "Not present"
        ),

        "message_id": email_message.get(
            "Message-ID",
            "Not present"
        ),
    }

    return details


def get_email_body(email_message: EmailMessage):
    """Extract the readable email body."""

    plain_text = ""
    html_text = ""

    for part in email_message.walk():

        content_type = part.get_content_type()

        # Skip attachments
        if part.get_filename():
            continue

        if content_type == "text/plain":

            try:
                plain_text += part.get_content()
            except Exception:
                continue

        elif content_type == "text/html":

            try:
                html_text += part.get_content()
            except Exception:
                continue

    # Prefer plain text when available
    if plain_text.strip():
        return plain_text

    return html_text


def extract_attachments(
    email_message: EmailMessage,
    output_folder="evidence/attachments"
):
    """
    Extract email attachments and save them
    to the evidence folder.
    """

    output_path = Path(output_folder)

    output_path.mkdir(
        parents=True,
        exist_ok=True
    )

    attachments = []

    for part in email_message.walk():

        filename = part.get_filename()

        if not filename:
            continue

        try:
            file_data = part.get_payload(
                decode=True
            )

            if file_data is None:
                continue

            # Keep the original filename simple
            filename = Path(filename).name

            attachment_path = (
                output_path / filename
            )

            # Avoid overwriting an existing file
            if attachment_path.exists():

                counter = 1

                while True:

                    new_name = (
                        f"{attachment_path.stem}_"
                        f"{counter}"
                        f"{attachment_path.suffix}"
                    )

                    new_path = (
                        output_path / new_name
                    )

                    if not new_path.exists():

                        attachment_path = new_path
                        break

                    counter += 1

            with open(
                attachment_path,
                "wb"
            ) as file:

                file.write(file_data)

            attachments.append(
                str(attachment_path)
            )

        except Exception as error:

            print(
                f"Could not extract attachment "
                f"{filename}: {error}"
            )

    return attachments


def get_received_headers(
    email_message: EmailMessage
):
    """Get all Received headers from the email."""

    return email_message.get_all(
        "Received",
        []
    )


def parse_email(file_path):
    """
    Parse the complete email and return
    the information needed by the SOC pipeline.
    """

    email_message = load_email(
        file_path
    )

    details = get_email_details(
        email_message
    )

    body = get_email_body(
        email_message
    )

    attachments = extract_attachments(
        email_message
    )

    received_headers = get_received_headers(
        email_message
    )

    return {
        "message": email_message,
        "details": details,
        "body": body,
        "attachments": attachments,
        "received_headers": received_headers
    }