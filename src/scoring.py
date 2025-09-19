from typing import Dict, Any, List

from src.utils.logging import logger

def calculate_risk_score(
    header_results: Dict[str, Any],
    url_results: List[Dict[str, Any]],
    attachment_results: List[Dict[str, Any]],
    weights: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Calculates a risk score based on analysis results and predefined weights.

    Args:
        header_results (Dict[str, Any]): Results from header analysis.
        url_results (List[Dict[str, Any]]): Results from URL analysis.
        attachment_results (List[Dict[str, Any]]): Results from attachment analysis.
        weights (Dict[str, Any]): A dictionary of weights for scoring.

    Returns:
        Dict[str, Any]: A dictionary containing the total score and breakdown.
    """
    total_score = 0
    score_breakdown = []

    header_weights = weights.get('headers', {})
    url_weights = weights.get('urls', {})
    attachment_weights = weights.get('attachments', {})

    # --- Header Score ---
    if header_results.get('spf_result') == 'fail':
        total_score += header_weights.get('spf_fail', 0)
        score_breakdown.append({'reason': 'SPF Check Failed', 'score': header_weights.get('spf_fail', 0)})
    if header_results.get('dkim_result') == 'fail':
        total_score += header_weights.get('dkim_fail', 0)
        score_breakdown.append({'reason': 'DKIM Check Failed', 'score': header_weights.get('dkim_fail', 0)})
    if header_results.get('dmarc_result') == 'fail':
        total_score += header_weights.get('dmarc_fail', 0)
        score_breakdown.append({'reason': 'DMARC Check Failed', 'score': header_weights.get('dmarc_fail', 0)})
    if header_results.get('from_return_path_mismatch'):
        total_score += header_weights.get('from_return_path_mismatch', 0)
        score_breakdown.append({'reason': 'From/Return-Path Mismatch', 'score': header_weights.get('from_return_path_mismatch', 0)})

    # --- URL Score (Corrected Logic) ---
    scored_urls = set() # To avoid scoring the same URL multiple times for different reasons
    for url in url_results:
        reasons = url.get('suspicion_reasons', [])
        original_url = url.get('original_url')

        # General suspicious score if any reason is present and not already scored
        if url.get('is_suspicious') and original_url not in scored_urls:
             total_score += url_weights.get('suspicious_domain', 0)
             score_breakdown.append({'reason': f'Suspicious URL ({original_url})', 'score': url_weights.get('suspicious_domain', 0)})
             scored_urls.add(original_url)

        # Specific scores based on reasons
        if "USES_URL_SHORTENER" in reasons:
            total_score += url_weights.get('shortened_url', 0)
            score_breakdown.append({'reason': f'URL is Shortened ({original_url})', 'score': url_weights.get('shortened_url', 0)})
        
        if "IP_ADDRESS_IN_HOST" in reasons:
            total_score += url_weights.get('ip_address_url', 0)
            score_breakdown.append({'reason': f'URL is IP Address ({original_url})', 'score': url_weights.get('ip_address_url', 0)})


    # --- Attachment Score ---
    for att in attachment_results:
        if att.get('is_dangerous'):
            total_score += attachment_weights.get('dangerous_file_type', 0)
            score_breakdown.append({'reason': f'Dangerous Attachment Type ({att["filename"]})', 'score': attachment_weights.get('dangerous_file_type', 0)})
        if att.get('contains_executable_in_zip'):
            total_score += attachment_weights.get('zip_with_executable', 0)
            score_breakdown.append({'reason': f'Zip Contains Executable ({att["filename"]})', 'score': attachment_weights.get('zip_with_executable', 0)})

    # Cap the score at 100
    final_score = min(total_score, 100)
    logger.info(f"Calculated final risk score: {final_score}")
    
    return {
        'total_score': final_score,
        'breakdown': score_breakdown
    }

if __name__ == '__main__':
    import json

    # Example usage with dummy data that matches the new structure
    dummy_weights = {
      "headers": {"spf_fail": 20, "dkim_fail": 20, "dmarc_fail": 25, "from_return_path_mismatch": 15},
      "urls": {"suspicious_domain": 30, "shortened_url": 25, "ip_address_url": 25},
      "attachments": {"dangerous_file_type": 40, "zip_with_executable": 50}
    }
    
    dummy_headers = {'spf_result': 'fail', 'from_return_path_mismatch': True}
    
    # This dummy data now correctly uses 'suspicion_reasons'
    dummy_urls = [
        {
            'original_url': 'http://1.2.3.4/login', 
            'is_suspicious': True, 
            'suspicion_reasons': ['IP_ADDRESS_IN_HOST', 'SUSPICIOUS_KEYWORDS_IN_URL']
        },
        {
            'original_url': 'http://bit.ly/xyz',
            'is_suspicious': True,
            'suspicion_reasons': ['USES_URL_SHORTENER']
        }
    ]
    
    dummy_attachments = [{'filename': 'file.exe', 'is_dangerous': True, 'contains_executable_in_zip': False}]

    score_results = calculate_risk_score(dummy_headers, dummy_urls, dummy_attachments, dummy_weights)
    
    print(json.dumps(score_results, indent=2))