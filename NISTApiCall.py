import json
import requests


# The following are all constants used to locate data on the local hard drive
API_KEY_LOCATION = 'key.txt'

def fetch_api_key():
    with open(API_KEY_LOCATION, 'r', encoding='utf-8') as f:
        data = f.readline()
    return data

def call_nist_api(use_api_key, url):
    api_key = ''
    if use_api_key:
        api_key += fetch_api_key()
    url += api_key

    response = requests.get(url)
    return json.loads(response.text)

if __name__ == '__main__':
    pass

