from flask import Flask, request, jsonify
from flask_cors import CORS
import tempfile
import os

# Import all your existing analysis functions
from src.ingest import parse_email_file, get_email_body
from src.headers import analyze_headers
from src.urls import extract_urls, analyze_all_urls
from src.attachments import analyze_attachments
from src.scoring import calculate_risk_score
from src.utils.logging import logger
import yaml

app = Flask(__name__)
CORS(app)  # Allows the HTML file to communicate with this server

# Load configuration once when the server starts
def load_config():
    config_path = os.path.join(os.path.dirname(__file__), 'config', 'config.yaml')
    try:
        with open(config_path, 'r') as f:
            logger.info("Configuration file loaded successfully for the server.")
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to load server configuration: {e}")
        return None

config = load_config()

@app.route('/analyze', methods=['POST'])
def analyze_email_endpoint():
    """
    This is the web endpoint that the index.html page will call.
    It receives the raw email source, runs the full Python analysis,
    and returns the final report as JSON.
    """
    if not config:
         return jsonify({"error": "Server configuration is missing or invalid."}), 500

    data = request.get_json()
    if not data or 'source' not in data:
        return jsonify({"error": "No email source provided."}), 400

    email_source = data['source']

    # Use a temporary file to work with your existing ingest functions
    try:
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, encoding='utf-8', suffix=".eml") as tmp:
            tmp.write(email_source)
            tmp_path = tmp.name
        
        # --- Run the Full Python Pipeline ---
        msg = parse_email_file(tmp_path)
        if not msg:
            return jsonify({"error": "Failed to parse email source."}), 400

        # 1. Ingest and Parse
        email_body = get_email_body(msg)
        raw_bytes = email_source.encode('utf-8')

        # 2. Run Analyses
        header_results = analyze_headers(msg, raw_bytes)
        urls = extract_urls(email_body)
        url_results = analyze_all_urls(urls, config.get('url_analysis', {}))
        # Note: we refactored analyze_attachments to take config
        attachment_results = analyze_attachments(msg, config)

        # 3. Score Results
        score_results = calculate_risk_score(
            header_results,
            url_results,
            attachment_results,
            config.get('scoring', {}).get('weights', {})
        )

        # 4. Combine into a final report
        final_report = {
            'summary': {
                'risk_score': score_results['total_score'],
                 # Determine risk level
                'risk_level': 'High' if score_results['total_score'] >= 80 else
                              'Medium' if score_results['total_score'] >= 60 else
                              'Low' if score_results['total_score'] >= 30 else 'Very Low',
            },
            'details': {
                'header_analysis': header_results,
                'url_analysis': url_results,
                'attachment_analysis': attachment_results,
                'score_breakdown': score_results['breakdown']
            }
        }
        
        return jsonify(final_report)

    except Exception as e:
        logger.error(f"An unexpected error occurred during analysis: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        if 'tmp_path' in locals() and os.path.exists(tmp_path):
            os.unlink(tmp_path)


if __name__ == '__main__':
    app.run(debug=True, port=5000)
