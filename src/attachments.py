from email.message import Message
from typing import List, Dict, Any
import os
import zipfile
import io

from src.utils.logging import logger

def analyze_attachments(msg: Message, config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Analyzes email attachments based on a provided configuration dictionary.

    Args:
        msg (Message): The email message object to analyze.
        config (Dict[str, Any]): A dictionary containing the analysis settings.
    
    Returns:
        List[Dict[str, Any]]: A list of analysis results for each attachment.
    """

    attachment_config = config.get('attachment_analysis', {})
    dangerous_extensions = set(attachment_config.get('dangerous_extensions', []))

    if not dangerous_extensions:
        logger.warning("No dangerous extensions configured. Attachment analysis may be ineffective.")

    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get('Content-Disposition') and 'attachment' in part.get('Content-Disposition'):
                filename = part.get_filename()
                if filename:
                    file_ext = os.path.splitext(filename)[1].lower()
                    analysis = {
                        'filename': filename,
                        'file_type': file_ext,
                        'is_dangerous': False,
                        'contains_executable_in_zip': False
                    }

                    if file_ext in dangerous_extensions:
                        analysis['is_dangerous'] = True
                        logger.warning(f"Found dangerous attachment type: {filename}")

                    if file_ext == '.zip':
                        try:
                            zip_data = part.get_payload(decode=True)
                            with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
                                for name in z.namelist():
                                    ext_in_zip = os.path.splitext(name)[1].lower()
                                    if ext_in_zip in dangerous_extensions:
                                        analysis['contains_executable_in_zip'] = True
                                        analysis['is_dangerous'] = True
                                        logger.warning(f"Found executable '{name}' inside zip attachment '{filename}'.")
                                        break
                        except Exception as e:
                            logger.error(f"Could not inspect zip file '{filename}': {e}")
                            
                    attachments.append(analysis)
    
    if attachments:
        logger.info(f"Found and analyzed {len(attachments)} attachments.")
    else:
        logger.info("No attachments found in the email.")

    return attachments

if __name__ == '__main__':
    from email import message_from_string

    # Example usage for isolated testing
    dummy_config = {
        'attachment_analysis': {
            'dangerous_extensions': ['.exe', '.bat', '.js']
        }
    }

    # Create a dummy email with an attachment for testing
    dummy_eml_content = """MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary"

--boundary
Content-Type: text/plain

This is the body.

--boundary
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="file.exe"

Some executable content
--boundary--"""

    dummy_msg = message_from_string(dummy_eml_content)
    
    results = analyze_attachments(dummy_msg, dummy_config)
    print("Analysis Results:")
    import json
    print(json.dumps(results, indent=2))

