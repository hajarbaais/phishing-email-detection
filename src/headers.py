from email.message import Message
from typing import Dict, Any, Optional
import re
import email.utils
import dns.resolver
import dkim
import spf
import ipaddress

from src.utils.logging import logger


def _get_domain_from_email(address: str) -> Optional[str]:
    """Robustly extracts the domain from an email address string."""
    if not address:
        return None
    _, addr = email.utils.parseaddr(address)
    if '@' in addr:
        return addr.split('@')[-1]
    return None


def _get_connecting_ip(msg: Message) -> Optional[str]:
    """
    Walks the 'Received' headers to find the first untrusted public IP address.
    Starts from the last header (closest to sender).
    """
    TRUSTED_RELAYS = [
        'google.com',
        'google.co.uk',
        'outlook.com',
        'office365.com',  
        'mailgun.org',
        'sendgrid.net',
        'amazonses.com',
        'zohomail.com'
    ]

    received_headers = msg.get_all('Received', [])
    if not received_headers:
        return None

   
    from_pattern = re.compile(
        r"from\s+([\w\.-]+)\s+\(.*?\[([0-9a-fA-F:\.]+)\]\)", re.IGNORECASE
    )

    for header in reversed(received_headers):
        match = from_pattern.search(header)
        if not match:
            continue

        host, ip_str = match.groups()
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue  

       
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            continue


        is_trusted = any(host.endswith(trusted_domain) for trusted_domain in TRUSTED_RELAYS)
        if not is_trusted:
            logger.info(f"Found untrusted IP: {ip_str} (host: {host})")
            return ip_str

    logger.warning("No untrusted public IP found in Received headers.")
    return None


def _check_dmarc(domain: str) -> str:
    """Performs a DNS lookup for a DMARC record."""
    if not domain:
        return 'not_found'
    try:
        dmarc_record = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for record in dmarc_record:
            if b'v=DMARC1' in record.to_wire():
                logger.info(f"Found DMARC record for {domain}")
                return 'pass'
        return 'fail'
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        logger.warning(f"No DMARC record found for {domain}")
        return 'not_found'
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as e:
        logger.error(f"DNS timeout or network error during DMARC check for {domain}: {e}")
        return 'dns_error'
    except Exception as e:
        logger.error(f"Error checking DMARC for {domain}: {e}")
        return 'error'


def _check_spf(ip: str, domain: str, sender: str) -> str:
    """Performs a full SPF check using the pyspf library."""
    if not all([ip, domain, sender]):
        return 'not_checked'
    try:
        result, _ = spf.check2(i=ip, s=sender, h=domain)
        logger.info(f"SPF check for IP {ip}, sender {sender}, domain {domain} resulted in: {result}")
        return result
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as e:
        logger.error(f"DNS timeout or network error during SPF check for {domain}: {e}")
        return 'dns_error'
    except Exception as e:
        logger.error(f"An unexpected error occurred during SPF check for {domain}: {e}")
        return 'error'


def analyze_headers(msg: Message, raw_email: bytes) -> Dict[str, Any]:
    """
    Analyzes email headers for signs of phishing using real-world checks.
    """
    results = {
        'spf_result': 'not_checked',
        'dkim_result': 'not_found',
        'dmarc_result': 'not_found',
        'from_return_path_mismatch': False,
        'from': msg.get('From'),
        'return_path': msg.get('Return-Path')
    }

    # --- 1. DKIM Verification ---
    try:
        is_dkim_valid = dkim.verify(raw_email)
        results['dkim_result'] = 'pass' if is_dkim_valid else 'fail'
        logger.info(f"DKIM verification result: {results['dkim_result']}")
    except (dkim.DKIMException, dns.exception.Timeout, dns.resolver.NoNameservers) as e:
        results['dkim_result'] = 'fail'
        logger.warning(f"DKIM verification failed (signature/DNS error): {e}")
    except Exception as e:
        results['dkim_result'] = 'error'
        logger.error(f"Unexpected error during DKIM verification: {e}")

    # --- 2. From/Return-Path Mismatch ---
    from_domain = _get_domain_from_email(results['from'])
    return_path_domain = _get_domain_from_email(results['return_path'])
    if from_domain and return_path_domain and from_domain != return_path_domain:
        results['from_return_path_mismatch'] = True
        logger.warning(f"Mismatch: From domain ({from_domain}) vs Return-Path domain ({return_path_domain})")

    # --- 3. DMARC Check ---
    if from_domain:
        results['dmarc_result'] = _check_dmarc(from_domain)

    # --- 4. SPF Check ---
    connecting_ip = _get_connecting_ip(msg)
    spf_sender = results['return_path']
    if spf_sender:
        spf_sender = spf_sender.strip('<>')

    if connecting_ip and return_path_domain and spf_sender:
        results['spf_result'] = _check_spf(
            ip=connecting_ip,
            domain=return_path_domain,
            sender=spf_sender
        )

    logger.info("Header analysis complete.")
    return results



