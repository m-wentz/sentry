import json
from flask import Blueprint, jsonify, request
from alerts.dlp_alert import single_dlp_msg, large_dlp_msg, single_dlp_int, large_dlp_int
from loguru import logger

# Initialize Slack & Splunk routes
splunk = Blueprint('splunk', __name__)
slack = Blueprint('slack', __name__)

@splunk.route('/splunk', methods=['POST'])
def splunk_route():
    """
    Endpoint to handle alerts from Splunk.
    
    Processes the JSON payload from Splunk to determine the type of alert
    and triggers appropriate message handling.
    """
    try:
        payload = request.json
        alert_id = payload['result']['Alert ID']
        logger.debug(f"Splunk alert received, Alert ID: {alert_id}")

        # Route the alert to the corresponding function based on its ID
        if alert_id == 'single_dlp':
            single_dlp_msg(payload)
        elif alert_id == 'large_dlp':
            large_dlp_msg(payload)
        else:
            logger.error(f"Unknown Alert ID: {alert_id}")
            return jsonify(success=False, error=f"Unknown Alert ID: {alert_id}"), 400

        return jsonify(success=True), 200

    # Catch any exceptions when accessing this route
    except Exception as e:
        logger.error("Failed to handle Splunk alert.")
        return handle_exception(e)


@slack.route('/slack', methods=['POST'])
def slack_route():
    """
    Endpoint to handle user interactions from Slack.
    
    Parses the interaction payload from Slack and routes it to the appropriate
    function based on the user's action.
    """
    try:
        form = request.form.get('payload')
        payload = json.loads(form)
        action_id = payload['actions'][0]['action_id']
        logger.debug(f"Slack interaction received, Action ID: {action_id}")

        # Route the action to the corresponding function based on its ID
        if action_id == 'single_dlp_auth':
            single_dlp_int(payload, action_id)
        elif action_id == 'single_dlp_unauth':
            single_dlp_int(payload, action_id)
        elif action_id == 'large_dlp_auth':
            large_dlp_int(payload, action_id)
        elif action_id == 'large_dlp_unauth':
            large_dlp_int(payload, action_id)
        else:
            logger.error(f"Unknown Action ID: {action_id}")
            return jsonify(success=False, error=f"Unknown Action ID: {action_id}"), 400

        return jsonify(success=True), 200
    
    # Catch any exceptions when accessing this route
    except Exception as e:
        logger.error("Failed to handle Slack interaction.")
        return handle_exception(e)


def handle_exception(e):
    """
    General exception handler to catch and log different types of errors.
    """
    if isinstance(e, json.JSONDecodeError):
        # Handle errors in JSON parsing
        logger.error(f"JSON parsing error: {e}")
        return jsonify(success=False, error="Invalid JSON format."), 400
    elif isinstance(e, KeyError):
        # Handle missing keys in the payload
        logger.error(f"Key error: {e}")
        return jsonify(success=False, error="Missing data in payload."), 400
    else:
        # Handle any other unexpected exceptions
        logger.error(f"Unexpected error: {e}")
        return jsonify(success=False, error="Internal server error."), 500