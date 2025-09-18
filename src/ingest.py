import os
import email
from typing import Optional
from email.message import Message
from src.utils.logging import logger

def parse_email_file(file_path: str) -> Optional[Message]:
    """Parses an .eml file into an email.Message object."""
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

def get_email_body(msg: Message) -> str:
    """
    Robustly extracts the text or HTML body from an email.Message object.
    It prioritizes HTML over plain text and handles missing payloads gracefully.
    """
    body = ""
    # For multipart messages, find the best text/html or text/plain part
    if msg.is_multipart():
        html_part = None
        plain_part = None
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            # Skip attachments
            if "attachment" in content_disposition:
                continue

            if content_type == "text/html":
                html_part = part
            elif content_type == "text/plain":
                plain_part = part

        # Prefer the HTML part if it exists, otherwise use the plain text part
        target_part = html_part if html_part else plain_part
        
        if target_part:
            payload = target_part.get_payload(decode=True)
            # CRITICAL FIX: Check if payload is not None before attempting to decode
            if payload:
                try:
                    body = payload.decode('utf-8')
                except UnicodeDecodeError:
                    body = payload.decode('latin-1', errors='ignore') # Fallback with error handling
    else:
        # For single-part messages, just get the payload
        payload = msg.get_payload(decode=True)
        # CRITICAL FIX: Check here as well
        if payload:
            try:
                body = payload.decode('utf-8')
            except UnicodeDecodeError:
                body = payload.decode('latin-1', errors='ignore')

    logger.info("Successfully extracted email body.")
    return body

