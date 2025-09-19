import os
import argparse
import yaml
from typing import Dict, Any

# Import all the necessary functions from your project modules
from src.ingest import parse_email_file, get_email_body
from src.headers import analyze_headers
from src.urls import extract_urls, analyze_all_urls
from src.attachments import analyze_attachments
from src.scoring import calculate_risk_score
from src.report import generate_report
from src.utils.logging import logger

def load_config(config_path: str = 'config/config.yaml') -> Dict[str, Any]:
    """Loads the main configuration file."""
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        logger.info("Configuration file loaded successfully.")
        return config
    except FileNotFoundError:
        logger.error(f"Configuration file not found at: {config_path}")
        return {}
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML configuration file: {e}")
        return {}

def main(email_path: str):
    """
    Main function to orchestrate the email analysis pipeline.
    """
    logger.info(f"Starting analysis for email: {email_path}")

    # 1. Load Configuration
    config = load_config()
    if not config:
        logger.error("Could not load configuration. Aborting analysis.")
        return

    # 2. Ingest and Parse Email
    msg = parse_email_file(email_path)
    if not msg:
        return # Error already logged by parse_email_file

    # Read raw email bytes for DKIM verification
    try:
        with open(email_path, 'rb') as f:
            raw_email_data = f.read()
    except Exception as e:
        logger.error(f"Could not read raw email file {email_path}: {e}")
        return
        
    email_body = get_email_body(msg)

    # 3. Run Analysis Modules
    logger.info("--- Starting Header Analysis ---")
    header_results = analyze_headers(msg, raw_email_data)

    logger.info("--- Starting URL Analysis ---")
    urls = extract_urls(email_body)
    # The full config is passed, as analyze_all_urls expects it
    url_results = analyze_all_urls(urls, config)

    logger.info("--- Starting Attachment Analysis ---")
    # Pass the config to the refactored function
    attachment_results = analyze_attachments(msg, config)

    # 4. Calculate Risk Score
    logger.info("--- Calculating Risk Score ---")
    
    # --- CRITICAL FIX IS HERE ---
    # We now pass the specific 'weights' dictionary from the config, not the whole 'scoring' block.
    score_weights = config.get('scoring', {}).get('weights', {})
    score_results = calculate_risk_score(
        header_results,
        url_results,
        attachment_results,
        score_weights # Pass the corrected dictionary
    )

    # 5. Generate Report
    logger.info("--- Generating Report ---")
    generate_report(
        email_path,
        header_results,
        url_results,
        attachment_results,
        score_results,
        config.get('paths', {}).get('reports_output', 'outputs/reports/')
    )

    logger.info(f"Analysis complete for {email_path}. Final score: {score_results.get('total_score')}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Analyze an email for phishing signs.")
    parser.add_argument("email_file", help="The path to the .eml email file to analyze.")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.email_file):
        print(f"Error: The file '{args.email_file}' does not exist.")
    else:
        main(args.email_file)