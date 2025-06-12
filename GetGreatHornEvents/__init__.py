import base64
import datetime
import hashlib
import hmac
import json
import logging
import os

import azure.functions as func
import requests

from .state_manager import BlobStateManager


class Config:
    def __init__(self):
        self.greathorn_url = "https://api.greathorn.com/"
        self.api_token = os.environ['gh_api_token']
        self.connection_string = os.environ['AzureWebJobsStorage']
        self.customer_id = os.environ['workspace_id']
        self.shared_key = os.environ['workspace_key']
        self.policy_table_name = "GreatHornPolicy"
        self.audit_table_name = "GreatHornAudit"
        self.chunk_size = 2000
        self.api_timeout = 30
        self.max_retries = 3

config = Config()


def validate_environment():
    """Validate all required environment variables are present"""
    required_vars = [
        'gh_api_token', 'AzureWebJobsStorage', 
        'workspace_id', 'workspace_key'
    ]
    missing = [var for var in required_vars if not os.environ.get(var)]
    if missing:
        raise ValueError(f"Missing required environment variables: {missing}")


def send_get(url, headers, params):
    """ sends a GET request to the defined endpoint """
    try:
        res = requests.get(url, headers=headers, params=params, timeout=30)
        res.raise_for_status()  # Raise an exception for bad status codes
        return res
    except requests.exceptions.RequestException as err:
        logging.error(f"GET request failed: {err}")
        raise
    except Exception as err:
        logging.error(f"Unexpected error in GET request: {err}")
        raise


def send_post(url, headers, json_data):
    """ sends a POST request to the defined endpoint """
    try:
        res = requests.post(url, headers=headers, json=json_data, timeout=30)
        res.raise_for_status()  # Raise an exception for bad status codes
        return res
    except requests.exceptions.RequestException as err:
        logging.error(f"POST request failed: {err}")
        raise
    except Exception as err:
        logging.error(f"Unexpected error in POST request: {err}")
        raise


def generate_date():
    """Generate date range with better error handling
    
    Returns:
        tuple: A tuple containing the past time and current time
    """
    current_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
    state = BlobStateManager(config.connection_string)
    
    try:
        past_time = state.get()
        if past_time:
            logging.info(f"Last checkpoint: {past_time}")
            # Validate the timestamp isn't too old (prevent huge data pulls)
            past_dt = datetime.datetime.fromisoformat(past_time.replace('Z', '+00:00'))
            # Ensure both datetimes are timezone-aware for proper comparison
            if (current_time - past_dt).days > 7:
                logging.warning("Last checkpoint is over 7 days old, limiting to 24 hours")
                past_time = (current_time - datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            else:
                # Use the retrieved timestamp as-is since it's valid and recent
                logging.info(f"Using checkpoint timestamp: {past_time}")
        else:
            logging.info("No previous checkpoint, fetching last 24 hours")
            past_time = (current_time - datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except Exception as e:
        logging.error(f"Error retrieving state: {e}")
        past_time = (current_time - datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    
    current_time_str = current_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    state.post(current_time_str)
    
    return past_time, current_time_str


def get_greathorn_audit(start_time, end_time):
    """ use the audit API to get the GreatHorn audit log
    
    Args:
        start_time (str): The start time of the audit log
        end_time (str): The end time of the audit log
    """
    audit_endpoint = "v2/administration/audit"
    headers = {
        "Authorization": f"Bearer {config.api_token}",
        "Accept": "application/json"
    }
    params = {'startDate': start_time, 'endDate': end_time}

    logging.info(f"Getting audit logs from GreatHorn from {start_time} to {end_time}...")
    results = send_get(f"{config.greathorn_url}{audit_endpoint}", headers, params)

    json_results = results.json()
    total_results = json_results['result']['total']
    events_list = json_results['result']['events']
    logging.info(f"Found {total_results} new audit log events")

    if total_results > 0:
        gen_chunks(events_list, config.audit_table_name)


def get_greathorn_events(start_time, end_time):
    """ use the search events API to get latest policy violations
    
    Args:
        start_time (str): The start time of the audit log
        end_time (str): The end time of the audit log
    """
    events_endpoint = "v2/search/events"
    headers = {
        "Authorization": f"Bearer {config.api_token}",
        "Accept": "application/json"
    }
    fields = [
        "policyMatched", "origin", "ip", "policyMatchedReasons", "policyActions",
        "reason", "status", "remediation", "replyTo", "returnPath", "source",
        "sourceDomain", "spamReport", "spf", "subject", "targets", "timestamp",
        "workflow", "messageId", "files", "eventId", "dmarc",
        "dkim", "displayName", "links"
    ]
    filters = [
        {
            "status": ["policy"],
            "startDate": start_time,
            "endDate": end_time
        }
    ]
    json_data = {
        "filters": filters,
        "fields": fields,
        "sort": "timestamp",
        "sortDir": "desc",
        "limit": 200
    }

    logging.info(f"Getting policy match events from GreatHorn from {start_time} to {end_time}...")

    post_results = send_post(
        f"{config.greathorn_url}{events_endpoint}", headers, json_data
    )
    json_results = post_results.json()
    result_count = len(json_results['results'])
    total_results = json_results['total']
    events_list = json_results['results']

    offset = 200

    logging.info(f"Found {total_results} new policy match events")

    # page through results if greater than max returned
    if total_results > 200:
        while result_count != 0 or result_count == 200:
            logging.info("Getting results from next offset...")
            json_data['offset'] = offset
            post_results = send_post(
                f"{config.greathorn_url}{events_endpoint}", headers, json_data
            )
            json_results = post_results.json()
            result_count = len(json_results['results'])

            events_list.extend(json_results['results'])
            offset = offset + 200

    # replace the links object in events_list with just the url items in the links object
    for event in events_list:
        if 'links' in event:
            new_links = []
            for link in event['links']:
                if 'url' in link:
                    new_links.append(link['url'])
            event['links'] = new_links

    if total_results > 0:
        gen_chunks(events_list, config.policy_table_name)


def gen_chunks_to_object(data, chunk_size=100):
    """Generate chunks of data
    
    Args:
        data (list): The data to process
        chunk_size (int): The size of the chunks to generate, default is 100
    """
    chunk = []
    for index, line in enumerate(data):
        if index % chunk_size == 0 and index > 0:
            yield chunk
            del chunk[:]
        chunk.append(line)
    yield chunk


def gen_chunks(data, table_name):
    """Generate chunks of data and send to the Azure Log Analytics API
    
    Args:
        data (list): The data to process
        table_name (str): The name of the table to send the data to, either "GreatHornPolicy" or "GreatHornAudit"
    """
    counter = 1
    for chunk in gen_chunks_to_object(data, chunk_size=config.chunk_size):
        logging.info(f"Sending chunk {counter}...")
        post_data(chunk, table_name)
        counter += 1


# Build the API signature
def build_signature(customer_id, shared_key, date, content_length, method,
                    content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = (
        method + "\n" + str(content_length) + "\n" + content_type + "\n" +
        x_headers + "\n" + resource
    )
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode()
    authorization = "SharedKey {}:{}".format(customer_id, encoded_hash)
    return authorization


# Build and send a request to the POST API
def post_data(chunk, log_type):
    """Post data to the Azure Log Analytics API
    
    Args:
        chunk (list): The data to send
        log_type (str): The type of log to send, either "GreatHornPolicy" or "GreatHornAudit"
    """
    body = json.dumps(chunk)
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.now(datetime.timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(
        config.customer_id, config.shared_key, rfc1123date, content_length, method,
        content_type, resource
    )
    uri = (
        'https://' + config.customer_id + '.ods.opinsights.azure.com' + resource +
        '?api-version=2016-04-01'
    )

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    try:
        response = requests.post(uri, data=body, headers=headers)

        if 200 <= response.status_code <= 299:
            logging.info(f"{len(chunk)} events added")
            return response.status_code
        elif response.status_code == 401:
            logging.error(
                f"The authentication credentials are incorrect or missing. Error code: {response.status_code}")
        else:
            logging.error(f"Something wrong. Error code: {response.status_code}")
        return None
    except Exception as err:
        logging.error(f"Something wrong. Exception error text: {err}")


def process_in_chunks(data, table_name, chunk_size=2000):
    """Process data in chunks and send directly
    
    Args:
        data (list): The data to process
        table_name (str): The name of the table to send the data to, either "GreatHornPolicy" or "GreatHornAudit"
        chunk_size (int): The size of the chunks to send
    """
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        logging.info(f"Sending chunk {(i // chunk_size) + 1}...")
        post_data(chunk, table_name)


def main(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.now(datetime.timezone.utc).replace(
        tzinfo=datetime.timezone.utc).isoformat()

    if mytimer.past_due:
        logging.info('The timer is past due!')

    logging.info('Python timer trigger function ran at %s', utc_timestamp)

    start_time, end_time = generate_date()
    
    get_greathorn_events(start_time, end_time)
    get_greathorn_audit(start_time, end_time)

# Call at module level
validate_environment()
