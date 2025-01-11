import json
import requests
import time


# The following are all constants used to locate data on the local hard drive
API_KEY_LOCATION = 'key.txt'

def fetch_api_key():
        with open(API_KEY_LOCATION, 'r', encoding='utf-8') as f:
            return f.readline().strip()

def call_nist_api(use_api_key, url):
    api_key = None
    try:
        if use_api_key:
            api_key = fetch_api_key()
    except FileNotFoundError:
        print('ERROR - API key file not found, continuing without an API key.')
        api_key = None

    if api_key is not None:
        response = requests.get(url, headers={'apiKey': api_key})
    else:
        response = requests.get(url)

    # Just an effort to not blast out the API
    time.sleep(2)
    if response.status_code != 200:
        raise ConnectionError(f'ERROR - http error code {response.status_code} bailing out')
    return json.loads(response.text)

if __name__ == '__main__':
    pass

