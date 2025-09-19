import os
import email
from email.message import Message
import yaml
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

# Import all your existing analysis functions
from src.utils.logging import logger
from src.ingest import parse_email_from_string, get_email_body
from src.headers import analyze_headers
from src.urls import extract_urls, analyze_all_urls
from src.attachments import analyze_attachments
from src.scoring import calculate_risk_score
from src.report import generate_report # Re-added for consistency, though not used in web response

app = Flask(__name__)
CORS(app) # Allows the HTML file to communicate with this server

def load_config():
    """Loads the main configuration file."""
    config_path = os.path.join(os.path.dirname(__file__), 'config', 'config.yaml')
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            logger.info("Configuration file loaded successfully for the server.")
            # Diagnostic print to be sure:
            # import json
            # print(json.dumps(config, indent=2))
            return config
    except FileNotFoundError:
        logger.error(f"FATAL: Configuration file not found at: {config_path}")
        return {}
    except yaml.YAMLError as e:
        logger.error(f"FATAL: Error parsing YAML file: {e}")
        return {}

config = load_config()

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyzes the raw email source provided in the request."""
    data = request.get_json()
    if not data or 'email_source' not in data:
        return jsonify({'error': 'Invalid request: email_source key missing'}), 400

    raw_email = data.get('email_source', '')

    if not raw_email:
        return jsonify({'error': 'No email source provided'}), 400

    logger.info("Received request for email analysis.")

    # --- Analysis Pipeline ---
    msg = parse_email_from_string(raw_email)
    if not msg:
        return jsonify({'error': 'Failed to parse email source'}), 500
    
    email_body = get_email_body(msg)
    
    # --- CRITICAL FIX: Ensure the full, correct config is passed ---
    header_results = analyze_headers(msg, raw_email.encode('utf-8'))
    urls = extract_urls(email_body)
    url_results = analyze_all_urls(urls, config)
    attachment_results = analyze_attachments(msg, config)
    
    # Scoring
    score_weights = config.get('scoring', {}).get('weights', {})
    score_results = calculate_risk_score(
        header_results, 
        url_results, 
        attachment_results, 
        score_weights
    )

    # Determine risk level from thresholds
    thresholds = config.get('thresholds', {})
    score = score_results.get('total_score', 0)
    risk_level = "Very Low"
    if score >= thresholds.get('high', 80):
        risk_level = "High"
    elif score >= thresholds.get('medium', 60):
        risk_level = "Medium"
    elif score >= thresholds.get('low', 30):
        risk_level = "Low"

    # --- Final Report ---
    report = {
        'summary': {
            'risk_score': score,
            'risk_level': risk_level
        },
        'details': {
            'header_analysis': header_results,
            'url_analysis': url_results,
            'attachment_analysis': attachment_results,
            'score_breakdown': score_results.get('breakdown', [])
        }
    }
    
    logger.info(f"Analysis complete. Sending report with score: {score}")
    return jsonify(report)

if __name__ == '__main__':
    # Flask will automatically look for 'index.html' in a 'templates' folder.
    # To run this, create a folder named 'templates' in your project's root
    # directory and move your 'index.html' file inside it.
    app.run(debug=True)

