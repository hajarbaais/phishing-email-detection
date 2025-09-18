import re
from typing import List, Dict, Any, Tuple, Optional
from urllib.parse import urlparse, unquote
from bs4 import BeautifulSoup
import requests
import whois
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.utils.logging import logger

_whois_cache: Dict[str, Any] = {}
_url_resolution_cache: Dict[str, str] = {}


def extract_urls(body: str) -> List[str]:
    """
    Extracts all unique URLs from an HTML or plain text body.
    It now uses a more precise regex to avoid capturing trailing HTML tags.
    """
    if not body:
        return []

    try:
        # Try to use the faster lxml parser
        soup = BeautifulSoup(body, 'lxml')
    except Exception:
        logger.warning("lxml parser not found. Falling back to 'html.parser'. For better performance, run 'pip install lxml'.")
        # Fall back to Python's built-in parser
        soup = BeautifulSoup(body, 'html.parser')
    
    # Extract URLs from <a> tags' href attributes
    urls = {a['href'] for a in soup.find_all('a', href=True)}

    # This pattern is more specific and avoids including trailing characters like '<' or '>'
    plain_text_urls = set(re.findall(
        r'\b(?:https?://|www\.)[^\s<>"]+\b', body, re.IGNORECASE
    ))

    # Combine, clean, and unquote the URLs
    all_urls = {unquote(url.strip('.,)')) for url in urls.union(plain_text_urls)}
    
    logger.info(f"Extracted {len(all_urls)} unique URLs from email body.")
    return list(all_urls)


def _resolve_url(url: str, session: requests.Session, max_redirects: int = 5) -> Tuple[Optional[str], List[str]]:
   
    if url in _url_resolution_cache:
        return _url_resolution_cache[url], []

    reasons = []
    try:
        current_url = url
        for _ in range(max_redirects):
            response = session.head(current_url, allow_redirects=False, timeout=3)
            if 300 <= response.status_code < 400 and 'Location' in response.headers:
                current_url = response.headers['Location']
            else:
                _url_resolution_cache[url] = current_url
                return current_url, reasons
        
        reasons.append("TOO_MANY_REDIRECTS")
        return None, reasons

    except requests.RequestException as e:
        logger.error(f"Could not resolve URL {url}: {e}")
        reasons.append("URL_RESOLUTION_FAILED")
        return None, reasons


def _get_domain_age(domain: str) -> Tuple[Optional[int], List[str]]:
   
    if domain in _whois_cache:
        return _whois_cache[domain]

    reasons = []
    try:
        domain_info = whois.whois(domain)
        if not domain_info.creation_date:
            reasons.append("WHOIS_NO_CREATION_DATE")
            return None, reasons
            
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        age = (datetime.now() - creation_date).days
        _whois_cache[domain] = (age, reasons)
        return age, reasons

    except Exception as e:
        logger.error(f"WHOIS lookup failed for {domain}: {e}")
        reasons.append("WHOIS_LOOKUP_FAILED")
        _whois_cache[domain] = (None, reasons)
        return None, reasons


def _analyze_single_url(url: str, session: requests.Session, config: Dict[str, Any]) -> Dict[str, Any]:
    
    analysis = {
        'original_url': url,
        'final_url': url,
        'is_suspicious': False,
        'suspicion_reasons': [],
        'domain_age_days': None
    }
    
    url_config = config.get('url_analysis', {})
    shorteners = set(url_config.get('url_shorteners', []))
    suspicious_tlds = set(url_config.get('suspicious_tlds', []))
    keywords = url_config.get('url_keywords', [])
    keyword_pattern = re.compile('|'.join(keywords), re.IGNORECASE) if keywords else None


    parsed_original = urlparse(url)
    if any(shortener in parsed_original.netloc for shortener in shorteners):
        analysis['is_suspicious'] = True # Shortened URLs are inherently suspicious
        analysis['suspicion_reasons'].append("USES_URL_SHORTENER")
        final_url, reasons = _resolve_url(url, session)
        analysis['suspicion_reasons'].extend(reasons)
        if final_url:
            analysis['final_url'] = final_url
        else:
            return analysis

    parsed_final = urlparse(analysis['final_url'])
    hostname = parsed_final.hostname

    if not hostname:
        analysis['is_suspicious'] = True
        analysis['suspicion_reasons'].append("INVALID_URL_NO_HOSTNAME")
        return analysis

    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ip_pattern, hostname):
        analysis['is_suspicious'] = True
        analysis['suspicion_reasons'].append("IP_ADDRESS_IN_HOST")

    age, reasons = _get_domain_age(hostname)
    analysis['suspicion_reasons'].extend(reasons)
    if age is not None:
        analysis['domain_age_days'] = age
        if age < 30:
            analysis['is_suspicious'] = True
            analysis['suspicion_reasons'].append("DOMAIN_AGE_TOO_LOW")
   
    try:
        tld = hostname.split('.')[-1]
        if tld in suspicious_tlds:
            analysis['is_suspicious'] = True
            analysis['suspicion_reasons'].append("SUSPICIOUS_TLD")
    except IndexError:
        pass 

    if hostname.count('.') >= 4:
        analysis['is_suspicious'] = True
        analysis['suspicion_reasons'].append("EXCESSIVE_SUBDOMAINS")

    # Now correctly flags the URL as suspicious if keywords are found.
    if keyword_pattern and (keyword_pattern.search(parsed_final.path) or keyword_pattern.search(parsed_final.query)):
        analysis['is_suspicious'] = True
        analysis['suspicion_reasons'].append("SUSPICIOUS_KEYWORDS_IN_URL")

    if parsed_final.scheme != 'https':
        # Not using HTTPS is a red flag, but not enough to mark as suspicious on its own
        analysis['suspicion_reasons'].append("NOT_USING_HTTPS")

    if parsed_final.username:
        analysis['is_suspicious'] = True
        analysis['suspicion_reasons'].append("USERNAME_IN_URL")

    return analysis


def analyze_all_urls(urls: List[str], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    
    results = []
    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_url = {executor.submit(_analyze_single_url, url, session, config): url for url in urls}
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results.append(result)
                    if result['is_suspicious']:
                        logger.warning(f"Suspicious URL found: {result['original_url']} -> {result['final_url']}. Reasons: {result['suspicion_reasons']}")
                except Exception as exc:
                    logger.error(f'URL analysis for {url} generated an exception: {exc}')
    
    return results

