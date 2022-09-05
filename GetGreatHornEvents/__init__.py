import base64
import datetime
import hashlib
import hmac
import json
import logging
import os

import azure.functions as func
import requests


GREATHORN_URL = "https://api.greathorn.com/"
GREATHORN_API_TOKEN = os.environ['gh_api_token']
customer_id = os.environ['workspace_id'] 
shared_key = os.environ['workspace_key']
policy_table_name = "GreatHornPolicyTEST"
audit_table_name = "GreatHornAuditTEST"


def send_get(url, headers, params):
    """ sends a POST request to the defined endpoint """
    try:
        res = requests.get(url, headers=headers, params=params)

        return res
    except Exception as err:
        logging.error(err)


def send_post(url, headers, json_data):
    """ sends a POST request to the defined endpoint """
    try:
        res = requests.post(url, headers=headers, json=json_data)

        return res
    except Exception as err:
        logging.error(err)


def get_greathorn_audit():
    """ use the audit API to get the GreatHorn audit log """
    audit_endpoint = "v2/administration/audit"
    end_date = datetime.datetime.now()
    end_date_iso = end_date.isoformat()
    start_date = end_date - datetime.timedelta(minutes=30)
    start_date_iso = start_date.isoformat()
    headers = {
        "Authorization": f"Bearer {GREATHORN_API_TOKEN}", 
        "Accept": "application/json"
    }
    params = {'startDate':start_date_iso, 'endDate':end_date_iso}

    logging.info("Getting audit logs from GreatHorn...")
    results = send_get(f"{GREATHORN_URL}{audit_endpoint}", headers, params)

    json_results = results.json()
    result_count = len(json_results['result'])
    total_results = json_results['result']['total']
    events_list = json_results['result']['events']
    logging.info(f"Found {total_results} new audit log events")

    body = json.dumps(events_list)
    post_data(customer_id, shared_key, body, audit_table_name)


def get_greathorn_events():
    """ use the search events API to get latest policy violations """
    events_endpoint = "v2/search/events"
    end_date = datetime.datetime.now()
    end_date_iso = end_date.isoformat()
    start_date = end_date - datetime.timedelta(minutes=30)
    start_date_iso = start_date.isoformat()
    headers = {
        "Authorization": f"Bearer {GREATHORN_API_TOKEN}", 
        "Accept": "application/json"
    }
    fields = [
        "policyMatched","origin","ip","policyMatchedReasons","policyActions",
        "reason","status","remediation","replyTo","returnPath","source",
        "sourceDomain","spamReport","spf","subject","targets","timestamp",
        "workflow","messageId","files","eventId","dmarc",
        "dkim","displayName"
    ]
    filters = [
        {
            "status": [ "policy"], 
            "startDate": start_date_iso, 
            "endDate": end_date_iso}
    ]
    json_data = {
        "filters": filters,
        "fields": fields,
        "sort": "timestamp",
        "sortDir": "desc",
        "limit": 200
    }

    logging.info("Getting policy match events from GreatHorn...")

    post_results = send_post(
        f"{GREATHORN_URL}{events_endpoint}", headers, json_data
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
            logging.info(f"Getting results from offset {offset}...")
            json_data['offset'] = offset
            post_results = send_post(
                f"{GREATHORN_URL}{events_endpoint}", headers, json_data
            )
            json_results = post_results.json()
            result_count = len(json_results['results'])

            events_list.extend(json_results['results'])
            offset = offset + 200
        
    body = json.dumps(events_list)
    post_data(customer_id, shared_key, body, policy_table_name)


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
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization


# Build and send a request to the POST API
def post_data(customer_id, shared_key, body, log_type):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(
        customer_id, shared_key, rfc1123date, content_length, method, 
        content_type, resource
    )
    uri = (
        'https://' + customer_id + '.ods.opinsights.azure.com' + resource + 
        '?api-version=2016-04-01'
    )

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri,data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        logging.info('Accepted')
    else:
        logging.error("Response code: {}".format(response.status_code))
        logging.error(response.content)


def main(mytimer: func.TimerRequest) -> None:
    utc_timestamp = datetime.datetime.utcnow().replace(
        tzinfo=datetime.timezone.utc).isoformat()

    if mytimer.past_due:
        logging.info('The timer is past due!')

    logging.info('Python timer trigger function ran at %s', utc_timestamp)

    get_greathorn_events()
    get_greathorn_audit()
