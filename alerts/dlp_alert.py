from flask import jsonify
from slack_sdk import WebClient
from loguru import logger
from threading import Timer
import os
import requests
import json
import re

# Load configuration from environment variables
ORG_NAME = os.getenv('ORG_NAME')
SLACK_TOKEN = os.getenv('SLACK_TOKEN')
SD_URL = os.getenv('SD_URL')
SD_TOKEN = os.getenv('SD_TOKEN')
SD_UID = os.getenv('SD_UID')
FEED_CH = os.getenv('FEED_CH')

# Initialize the Slack client
slack_client = WebClient(token=SLACK_TOKEN)


def single_dlp_msg(payload):
    """
    Sends a Slack message to notify an employee about a document download by an unknown actor.

    Args:
    payload (dict): A dictionary containing Splunk alert key-value pairs.
    """
    logger.debug("Initializing message...")
    try:
        # Extract relevant information from the payload
        employee = payload['result']['Employee']
        actor = payload['result']['Actor']
        doc = payload['result']['Document']
        doc_url = payload['result']['URL']
        # A unique identifier is included with each alert to allow for ServiceDesk incident querying
        ticket_id = payload['result']['Ticket ID']

        # Safety checks for required data
        if not all([employee, actor, doc, doc_url, ticket_id]):
            logger.error("Missing required data in the payload.")
            return jsonify(success=False, error="Incomplete payload data."), 400

        # Retrieve the employee's Slack UID based on their email within the payload
        get_uid = slack_client.users_lookupByEmail(email=employee)
        uid = get_uid['user']['id']

        # Log extracted information for debugging
        logger.debug(f"""Employee: {employee}, Actor: {actor}, Document: \"{doc}\",
                     URL: {doc_url}, Slack UID: {uid}""")

       # Compose and send a Slack message to the employee
        logger.debug("Sending message...")
        response = slack_client.chat_postMessage(
            channel=uid, text=f"{actor} has downloaded a document owned by you", blocks=[
                # Define the message structure with sections and interactive elements
                {
                    "type": "section",
                    # Include the Ticket ID in the message payload to allow for incident querying post interaction
                    "block_id": f"{ticket_id}",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"A document owned by you was downloaded outside of {ORG_NAME} by an unknown user. Please confirm that this download by {actor} was authorized by you."
                    }
                },
                {
                    "type": "section",
                    "block_id": "single_dlp_doc",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"<{doc_url}|{doc}>"
                    }
                },
                {
                    "type": "input",
                    "block_id": "single_dlp_input",
                    "element": {
                        "type": "plain_text_input",
                        "action_id": "single_dlp_input"
                    },
                    "label": {
                        "type": "plain_text",
                        "text": "Reason (Required):",
                        "emoji": True
                    }
                },
                {
                    "type": "actions",
                    "block_id": "single_dlp_buttons",
                    "elements": [
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "Authorized"
                            },
                            "style": "primary",
                            "value": "2",
                            "action_id": "single_dlp_auth"
                        },
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "Unauthorized"
                            },
                            "style": "danger",
                            "value": "3",
                            "action_id": "single_dlp_unauth"
                        }
                    ]
                }
            ])

        # Verify the message has been sent
        if response.status_code == 200:
            logger.debug("Message sent!")

            # Add comment to existing ServiceDesk incident
            incident_comment(
                f"Contacted {employee}.<br>Awaiting response...", ticket_id)

            # Update existing ServiceDesk incident's state and priority
            update_incident(ticket_id, state="In Progress", priority="Medium")
        else:
            logger.error(
                f"Failed to send Slack message, status code: {response.status_code}")

    # Catch any exceptions when sending the initial Slack message
    except Exception as e:
        logger.error(
            f"Failed to send Slack message. ({single_dlp_msg.__name__})")
        return handle_exception(e)


def single_dlp_int(payload, action_id):
    """
    Handle Slack interactions made by an employee for an external document download.

    Parameters:
    payload (dict): A dictionary containing Slack interaction key-value pairs.
    action_id (str): The action made by the Employee.
    """
    logger.debug("Initializing response...")
    try:
        # Extract relevant values from the payload
        timestamp = payload['message']['ts']
        channel = payload['channel']['id']
        uid = payload['user']['id']
        username = payload['user']['name']
        ticket_id = payload['message']['blocks'][0]['block_id']

        # Extract the actor email
        actor_match = re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}(?=\|)',
                                payload['message']['text'])
        if actor_match:
            actor = actor.group(0)
        else:
            logger.error("Actor email not found in the payload.")
            return jsonify(success=False), 400

        # Extract the user's input value
        input_value = payload['state']['values']['single_dlp_input']['single_dlp_input']['value']

        # Log extracted information for debugging
        logger.debug(f"""Timestamp: {timestamp}, Channel: {channel}, UID: {uid},
                     Username: {username}, Actor: {actor}, Ticket ID: {ticket_id}""")
        logger.debug(f"User input: \"{input_value}\"")

        # Check for empty input and handle it
        if input_value == None:
            logger.debug(f"No input detected by {username}!")
            no_input(uid)
            return jsonify(success=True), 200

        # Delete any no input messages sent to the employee after valid input submisssion
        if action_id in ['single_dlp_auth', 'single_dlp_unauth']:
            if no_input_msgs:
                for ts in no_input_msgs:
                    slack_client.chat_delete(channel=channel, ts=ts,
                                             token=SLACK_TOKEN)
                no_input_msgs.clear()

        # Handle document download authorization by the employee
        if action_id == 'single_dlp_auth':
            try:
                # Compose and send a Slack response to the employee confirming the authorization
                logger.debug("Sending response...")
                response = slack_client.chat_update(
                    token=SLACK_TOKEN, channel=channel, ts=timestamp,
                    text="Thank you for authorizing this user. Our security team has been notified", blocks=[
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": "Thank you for authorizing this user. Our security team has been notified."
                            }
                        }
                    ])

                if response.status_code == 200:
                    logger.debug("Response sent!")

                    # Notify #sentry-feed about the employee's authorization
                    feed_msg(
                        f"{username} has authorized an external download by {actor}, updating exisitng ServiceDesk ticket...")

                    # Schedule the deletion of the employee's confirmation message to maintain channel cleanliness
                    t = Timer(60.0, delete_msg, args=[
                              SLACK_TOKEN, channel, response['ts']])
                    t.start()

                    # Add comment to existing ServiceDesk incident
                    incident_comment(
                        f"{username} has authorized this document download.<br>Reason: {input_value}", ticket_id)

                    # Update existing ServiceDesk incident's priority to "Medium"
                    update_incident(
                        ticket_id, state="In Progress", priority="Medium")

            except Exception as e:
                logger.error(
                    f"Failed to send Slack response. ({single_dlp_int.__name__}: {action_id})")
                return handle_exception(e)

        # Handle document download unauthorization by the employee
        elif action_id == 'single_dlp_unauth':
            try:
                # Compose and send a Slack response to the employee confirming the unauthorization
                logger.debug("Sending response...")
                response = slack_client.chat_update(token=SLACK_TOKEN, channel=channel, ts=timestamp, text="Thank you for unauthorizing this user. Our security team has been notified", blocks=[
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "Thank you for unauthorizing this user. Our security team has been notified."
                        }
                    }
                ])

                if response.status_code == 200:
                    logger.debug("Response sent!")

                    # Notify #sentry-feed about the employee's unauthorization
                    feed_msg(
                        f"{username} has unauthorized an external download by {actor}, updating exisitng ServiceDesk ticket...")

                    # Schedule the deletion of the employee's confirmation message to maintain channel cleanliness
                    t = Timer(60.0, delete_msg, args=[
                              SLACK_TOKEN, channel, response['ts']])
                    t.start()

                    # Add comment to existing ServiceDesk incident
                    incident_comment(
                        f"{username} has unauthorized this document download!<br>Reason: {input_value}", ticket_id)

                    # Update existing ServiceDesk incident's priority to "Critical"
                    update_incident(
                        ticket_id, state="In Progress", priority="Critical")

            except Exception as e:
                logger.error(
                    f"Failed to send Slack response. ({single_dlp_int.__name__}: {action_id})")
                return handle_exception(e)

    # Catch any exceptions when handling Slack interactions
    except Exception as e:
        logger.error(
            f"Failed to handle Slack interaction. ({single_dlp_int.__name__})")
        return handle_exception(e)


def large_dlp_msg(payload):
    """
    Send a Slack message to an employee when a large document download is made by a unknown actor.

    Parameters:
    payload (dict): A dictionary containing Splunk key-value pairs.
    """
    logger.debug("Initializing message...")
    try:
        # Extract relevant values from the payload
        employee = payload['result']['Employee']
        actor = payload['result']['Actor']
        docs = payload['result']['Documents']
        doc_urls = payload['result']['URLs']
        ticket_id = payload['result']['Ticket ID']

        # Safety checks for required data
        if not all([employee, actor, docs, doc_urls, ticket_id]):
            logger.error("Missing required data in the payload.")
            return jsonify(success=False, error="Incomplete payload data."), 400

        # Retrieve the employee's Slack UID based on their email within the payload
        get_uid = slack_client.users_lookupByEmail(email=employee)
        uid = get_uid['user']['id']

        # Log extracted information for debugging
        logger.debug(f"""Employee: {employee}, Actor: {actor}, Documents: \"{docs}\",
                     URLs: {doc_urls}, Slack UID: {uid}""")

        # Compile a document section for each document
        logger.debug("Compiling message...")
        doc_section = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"<{url}|{document}>"
                }
            } for document, url in zip(docs, doc_urls)]

        # Compose and send a Slack message to the employee
        logger.debug("Sending message...")
        response = slack_client.chat_postMessage(
            channel=uid, text=f"{actor} has downloaded several documents owned by you", unfurl_links=False, blocks=[
                # Define the message structure with sections and interactive elements
                {
                    "type": "section",
                    # Include the Ticket ID in the message payload to allow for incident querying post interaction
                    "block_id": f"{ticket_id}",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"Several documents owned by you were downloaded outside of {ORG_NAME} by an unknown user. Please confirm that these downloads by {actor} are authorized by you."
                    }
                },
                # Insert compiled document sections
                *doc_section,
                {
                    "type": "input",
                    "block_id": "large_dlp_input",
                    "element": {
                        "type": "plain_text_input",
                        "action_id": "large_dlp_input"
                    },
                    "label": {
                        "type": "plain_text",
                        "text": "Reason (Required):",
                        "emoji": True
                    }
                },
                {
                    "type": "actions",
                    "block_id": "large_dlp_buttons",
                    "elements": [
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "Authorized"
                            },
                            "style": "primary",
                            "value": "2",
                            "action_id": "large_dlp_auth"
                        },
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "Unauthorized"
                            },
                            "style": "danger",
                            "value": "3",
                            "action_id": "large_dlp_unauth"
                        }
                    ]
                }
            ])

        # Verify the message has been sent
        if response.status_code == 200:
            logger.debug("Message sent!")

            # Add comment to existing ServiceDesk incident
            incident_comment(
                f"Contacted {employee}.<br>Awaiting response...", ticket_id)

            # Update existing ServiceDesk incident's state to "In Progress"
            update_incident(ticket_id, state="In Progress", priority="High")

    # Catch any exceptions when sending the initial Slack message
    except Exception as e:
        logger.error(
            f"Failed to send Slack message. ({large_dlp_msg.__name__})")
        return handle_exception(e)


# Handle Slack interactions made by a user for multiple documents downloaded externally
def large_dlp_int(payload, action_id):
    """
    Handle Slack interactions made by an employee for a large external document download.

    Parameters:
    payload (dict): A dictionary containing Slack interaction key-value pairs.
    action_id (str): The action made by the Employee.
    """
    logger.debug("Initializing response...")
    try:
        # Extract relevant values from the payload
        timestamp = payload['message']['ts']
        channel = payload['channel']['id']
        uid = payload['user']['id']
        username = payload['user']['name']
        ticket_id = payload['message']['blocks'][0]['block_id']

        # Extract the actor email
        actor_match = re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}(?=\|)',
                                payload['message']['text'])
        if actor_match:
            actor = actor.group(0)
        else:
            logger.error("Actor email not found in the payload.")
            return jsonify(success=False), 400

        # Extract the user's input value
        input_value = payload['state']['values']['large_dlp_input']['large_dlp_input']['value']

        # Log extracted information for debugging
        logger.debug(f"""Timestamp: {timestamp}, Channel: {channel}, UID: {uid},
                     Username: {username}, Actor: {actor}, Ticket ID: {ticket_id}""")
        logger.debug(f"User input: \"{input_value}\"")

        # Check for empty input and handle it
        if input_value == None:
            logger.debug(f"No input detected by {username}!")
            no_input(uid)
            return jsonify(success=True), 200

        # Delete any no input messages sent to the employee after valid input submisssion
        if action_id in ['large_dlp_auth', 'large_dlp_auth']:
            if no_input_msgs:
                for ts in no_input_msgs:
                    slack_client.chat_delete(channel=channel, ts=ts,
                                             token=SLACK_TOKEN)
                no_input_msgs.clear()

        # Handle multiple document downloads authorized by the employee
        if action_id == 'large_dlp_auth':
            try:
                # Compose and send a Slack response to the employee confirming the authorization
                logger.debug("Sending response...")
                response = slack_client.chat_update(
                    token=SLACK_TOKEN, channel=channel, ts=timestamp,
                    text="Thank you for authorizing this user. Our security team has been notified", blocks=[
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": "Thank you for authorizing this user. Our security team has been notified."
                            }
                        }
                    ])
                if response.status_code == 200:
                    logger.debug("Response sent!")

                    # Notify #sentry-feed about the employee's authorization
                    feed_msg(f"{username} has authorized multiple external downloads by {actor}, submitting a ServiceDesk ticket for review...")  # noqa

                    # Schedule the deletion of the employee's confirmation message to maintain channel cleanliness
                    t = Timer(60.0, delete_msg, args=[
                        SLACK_TOKEN, channel, response['ts']])
                    t.start()

                    # Add comment to existing ServiceDesk incident
                    incident_comment(
                        f"{username} has authorized the download of these documents. <br>Reason: {input_value}", ticket_id)

                    # Update existing ServiceDesk incident's priority to "High"
                    update_incident(
                        ticket_id, state="In Progress", priority="High")

            except Exception as e:
                logger.error(
                    f"Failed to send Slack response. ({large_dlp_int.__name__}: {action_id})")
                return handle_exception(e)

        # Handle multiple document downloads unauthorized by the employee
        elif action_id == 'large_dlp_unauth':
            try:
                # Compose and send a Slack response to the employee confirming the unauthorization
                logger.debug("Sending response...")
                response = slack_client.chat_update(
                    token=SLACK_TOKEN, channel=channel, ts=timestamp,
                    text="Thank you for unauthorizing this user. Our security team has been notified", blocks=[
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": "Thank you for unauthorizing this user. Our security team has been notified."
                            }
                        }
                    ])
                if response.status_code == 200:
                    logger.debug("Response sent!")

                    # Notify #sentry-feed about the employee's authorization
                    feed_msg(f"{username} has unauthorized multiple external downloads by {actor}, submitting a ServiceDesk ticket for review...")  # noqa

                    # Schedule the deletion of the employee's confirmation message to maintain channel cleanliness
                    t = Timer(60.0, delete_msg, args=[
                        SLACK_TOKEN, channel, response['ts']])
                    t.start()

                    # Add comment to existing ServiceDesk incident
                    incident_comment(
                        f"{username} has unauthorized the download of these documents! <br>Reason: {input_value}", ticket_id)

                    # Update existing ServiceDesk incident's priority to "Critical"
                    update_incident(
                        ticket_id, state="In Progress", priority="Critical")

            except Exception as e:
                logger.error(
                    f"Failed to send Slack response. ({large_dlp_int.__name__}: {action_id})")
                return handle_exception(e)

    except Exception as e:
        logger.error(
            f"Failed to send Slack response. ({large_dlp_int.__name__}: {action_id})")
        return handle_exception(e)


# Query for exisiting ServiceDesk incident and add a comment
def incident_comment(comment_body, ticket_id):
    try:
        logger.debug("Querying for existing incident...")
        # Start and automatically close the session with each function call to mitigate SSL issues
        with requests.Session() as sd_session:
            sd_session.headers.update({
                "Content-Type": "application/json",
                "X-Samanage-Authorization": SD_TOKEN,
                "Accept": "application/json"
            })

        # Query for the incident ID using "Ticket ID" generated in alert
        incident_query = sd_session.get(SD_URL, params={'query': ticket_id})

        # Verify the incident ID has been found successfully
        if incident_query.status_code == 200:
            query_data = incident_query.json()
            incident_id = query_data[0]['id']
            logger.debug(f"Incident found! ({incident_id})")

        # Specify comment body
        sd_comment = {
            "body": f"{comment_body}",
            "is_private": "false",
            "user_id": f"{SD_UID}"
        }

        # Post comment to existing incident
        logger.debug(f"Adding comment to incident...")
        sd_com_response = sd_session.post(
            f"{SD_URL}/{incident_id}/comments", data=json.dumps(sd_comment))

        # Verify the comment has been added successfully
        if sd_com_response.status_code == 200:
            logger.debug(
                f"Added comment successfully! ({incident_id}: \"{comment_body}\")")
            return jsonify(success=True), 200

    # Handle any exceptions when updating the incident
    except Exception as e:
        logger.error(
            f"Failed to add comment to incident. ({incident_id}: \"{comment_body}\")")
        return handle_exception(e)


# Query for exisiting ServiceDesk incident and update it's state
def update_incident(ticket_id, state="", priority=""):
    try:
        # Start and automatically close the session with each function call to mitigate SSL issues
        with requests.Session() as sd_session:
            sd_session.headers.update({
                "Content-Type": "application/json",
                "X-Samanage-Authorization": SD_TOKEN,
                "Accept": "application/json"
            })

        # Query for the incident ID using "Ticket ID" generated in alert
        logger.debug("Querying for existing incident...")
        incident_query = sd_session.get(SD_URL, params={'query': ticket_id})

        # Verify the incident ID has been found successfully
        if incident_query.status_code == 200:
            query_data = incident_query.json()
            incident_id = query_data[0]['id']
            logger.debug(f"Incident found! ({incident_id})")

        # Specify incident state change
        sd_state_change = {
            "incident": {
                "state": f"{state}",
                "priority": f"{priority}"
            }
        }

        # Update existing incident state
        logger.debug(f"Updating incident...")
        sd_state_response = sd_session.put(
            f"{SD_URL}/{incident_id}", data=json.dumps(sd_state_change))

        # Verify the state has been updated successfully
        if sd_state_response.status_code == 200:
            logger.debug(
                f"Updated incident! ({incident_id}: \"{state}\" \"{priority}\")")
            return jsonify(success=True), 200

    # Handle any exceptions when updating the incident
    except Exception as e:
        logger.error(
            f"Failed to update incident. ({incident_id}: \"{state}\" \"{priority}\")")
        return handle_exception(e)


# Maintains a list of timestamps corresponding to reminders sent to employees for missing inputs
no_input_msgs = []

# Prompts an employee via Slack when a required input is missing


def no_input(user_id):
    # Enables modification of the global list no_input_msgs within this function
    global no_input_msgs
    try:
        # Send the reminder message via Slack
        logger.debug("Sending response...")
        response = slack_client.chat_postMessage(channel=user_id, text="Please fill out the required field", blocks=[
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "Please fill out the required field."
                }
            }
        ])

        # Verify the message was sent successfully
        if response.status_code == 200:
            logger.debug("Response sent!")

            # Storing the timestamp of the sent message for deletion
            no_input_msgs.append(response['ts'])
            return jsonify(success=True), 200

    # Catch any exceptions when sending the no input response
    except Exception as e:
        logger.debug(f"Failed to send no input response. ({e})")
        return jsonify(success=False), 400


# Deletes Slack messages, mainly used for maintaining channel cleanliness
def delete_msg(slack_token, channel, ts):
    slack_client.chat_delete(token=slack_token, channel=channel, ts=ts)

# Post activity logs or notifications in a dedicated Slack channel


def feed_msg(message):
    slack_client.chat_postMessage(channel=FEED_CH, text=message, blocks=[
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": message
            }
        }
    ])

# General exception handler for various functions


def handle_exception(e):
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
