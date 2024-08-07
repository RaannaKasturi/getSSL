import json
import sys
from google.oauth2 import service_account
from google.cloud.security.publicca import PublicCertificateAuthorityServiceClient as productionclient
from google.cloud.security.publicca_v1beta1 import PublicCertificateAuthorityServiceClient as testingclient

def gen_google_eab(test:bool=True):
    with open('sak.json', 'r') as file:
        service_account_info = json.load(file)
    credentials = service_account.Credentials.from_service_account_info(service_account_info)
    if test:
        client = testingclient(credentials=credentials)
    else:
        client = productionclient(credentials=credentials)
    project_id = service_account_info['project_id']
    parent = f"projects/{project_id}"
    response = client.create_external_account_key(parent=parent)
    kid = response.key_id
    hmac = response.b64_mac_key
    return kid, hmac