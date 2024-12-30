import json
import requests
import time


# The following are all constants used to locate data on the local hard drive
API_KEY_LOCATION = 'key.txt'

def fetch_api_key():
    try:
        with open(API_KEY_LOCATION, 'r', encoding='utf-8') as f:
            data = f.readline().strip()
    except FileNotFoundError:
        print('ERROR - API key file not found, continuing without an API key.')
        data = ''
    return data

def call_nist_api(use_api_key, url):
    api_key = None
    if use_api_key:
        api_key = fetch_api_key()

    if api_key is not None:
        response = requests.get(url, headers={'apiKey': api_key})
    else:
        response = requests.get(url)

    # Just an effort to not blast out the API
    time.sleep(1)

    return json.loads(response.text)

if __name__ == '__main__':
    pass

