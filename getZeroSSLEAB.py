import requests
import os
from dotenv import load_dotenv

def gen_zero_ssl_eab():
    load_dotenv()    
    apikey = os.getenv("ZEROSSLAPI")
    url = "https://api.zerossl.com/acme/eab-credentials"
    headers = {'Content-Type': 'application/json'}
    resp = requests.post(url, params={'access_key': apikey}, headers=headers)
    print(resp.json())
    if resp.json()['success'] == False:
        print("Error: ", resp.json()['error'])
        return "Error", "Error"
    else:
        kid = resp.json()['eab_kid']
        hmac = resp.json()['eab_hmac_key']
    return kid, hmac