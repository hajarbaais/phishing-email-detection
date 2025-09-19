import os
import email
from typing import Optional
from email.message import Message
from src.utils.logging import logger

def parse_email_file(file_path: str) -> Optional[Message]:
    """Parses an .eml file from a file path."""
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        return None
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            msg = email.message_from_file(f)
        logger.info(f"Successfully parsed email file: {file_path}")
        return msg
    except Exception as e:
        logger.error(f"Could not parse email file {file_path}: {e}")
        return None

def parse_email_from_string(raw_email: str) -> Optional[Message]:
    """Parses an email from a raw string."""
    try:
        msg = email.message_from_string(raw_email)
        logger.info("Successfully parsed email from raw string.")
        return msg
    except Exception as e:
        logger.error(f"Could not parse email from raw string: {e}")
        return None

def get_email_body(msg: Message) -> str:
    """
    Robustly extracts the text or HTML body from an email.Message object.
    It prioritizes HTML over plain text.
    """
    body = ""
    if msg.is_multipart():
        html_part = None
        plain_part = None
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if "attachment" in content_disposition:
                continue

            if content_type == "text/html":
                html_part = part
            elif content_type == "text/plain":
                plain_part = part

        target_part = html_part if html_part else plain_part
        
        if target_part:
            payload = target_part.get_payload(decode=True)
            if payload:
                try:
                    body = payload.decode('utf-8')
                except UnicodeDecodeError:
                    body = payload.decode('latin-1', errors='ignore')
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            try:
                body = payload.decode('utf-8')
            except UnicodeDecodeError:
                body = payload.decode('latin-1', errors='ignore')

    logger.info("Successfully extracted email body.")
    return body

