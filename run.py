from flask import Flask
from routes import splunk, slack
from loguru import logger
import sys
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logger
logger.remove()  # Removes default logger
# Add a new logger that outputs to stderr with custom formatting, level set to DEBUG
logger.add(sys.stderr, format="{time} {level} {message}", level="DEBUG")

# Initialize the Flask app
webserver = Flask(__name__)

# Register webservers routes for Slack & Splunk
webserver.register_blueprint(splunk)
webserver.register_blueprint(slack)

# Main entry point for the Flask application
if __name__ == '__main__':
    # Retrieve host, port, and SSL paths from environment variables with defaults
    host = os.getenv('FLASK_HOST', '127.0.0.1')
    port = int(os.getenv('FLASK_PORT', 5000))
    ssl_cert_path = os.getenv('SSL_CERT_PATH', 'path/to/certificate.crt')
    ssl_key_path = os.getenv('SSL_KEY_PATH', 'path/to/private.key')

    # Run the Flask app with SSL
    # Note: Set debug=False in a production environment for security reasons
    webserver.run(host=host, port=port, debug=True,
                  ssl_context=(ssl_cert_path, ssl_key_path))
