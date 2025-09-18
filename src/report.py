import json
import os
from datetime import datetime
from typing import Dict, Any

from src.utils.logging import logger

def generate_report(
    email_path: str,
    header_results: Dict[str, Any],
    url_results: list,
    attachment_results: list,
    score_results: Dict[str, Any],
    output_dir: str
) -> None:
    """
    Generates a JSON report of the analysis.

    Args:
        email_path (str): Path to the original email file.
        header_results (Dict[str, Any]): Header analysis results.
        url_results (list): URL analysis results.
        attachment_results (list): Attachment analysis results.
        score_results (Dict[str, Any]): Scoring results.
        output_dir (str): Directory to save the report.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    email_filename = os.path.basename(email_path)
    report_filename = f"{os.path.splitext(email_filename)[0]}_{timestamp}.json"
    report_path = os.path.join(output_dir, report_filename)

    # Determine risk level
    score = score_results['total_score']
    if score > 80:
        risk_level = 'High'
    elif score > 50:
        risk_level = 'Medium'
    elif score > 20:
        risk_level = 'Low'
    else:
        risk_level = 'Very Low'

    report_data = {
        'metadata': {
            'email_file': email_path,
            'analysis_timestamp': datetime.now().isoformat(),
            'report_file': report_path
        },
        'summary': {
            'risk_score': score,
            'risk_level': risk_level,
        },
        'details': {
            'header_analysis': header_results,
            'url_analysis': url_results,
            'attachment_analysis': attachment_results,
            'score_breakdown': score_results['breakdown']
        }
    }

    try:
        os.makedirs(output_dir, exist_ok=True)
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=4)
        logger.info(f"Successfully generated report at {report_path}")
    except Exception as e:
        logger.error(f"Failed to write report to {report_path}: {e}")

if __name__ == '__main__':
    # Dummy data for testing
    dummy_email_path = 'data/raw/phishing/sample_phish.eml'
    dummy_headers = {'spf_record': 'fail'}
    dummy_urls = [{'url': 'http://bad.com', 'is_suspicious': True}]
    dummy_attachments = []
    dummy_score = {'total_score': 70, 'breakdown': [{'reason': 'SPF Fail', 'score': 70}]}
    dummy_output_dir = 'outputs/reports'

    generate_report(dummy_email_path, dummy_headers, dummy_urls, dummy_attachments, dummy_score, dummy_output_dir)
    print(f"Dummy report generated in {dummy_output_dir}")
