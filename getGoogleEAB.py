import json
import base64
from google.oauth2 import service_account
from google.cloud.security.publicca import PublicCertificateAuthorityServiceClient

def getGoogleEAB():
    with open('sak.json', 'r') as file:
        service_account_info = json.load(file)
    credentials = service_account.Credentials.from_service_account_info(service_account_info)
    client = PublicCertificateAuthorityServiceClient(credentials=credentials)
    project_id = service_account_info['project_id']
    parent = f"projects/{project_id}"
    response = client.create_external_account_key(parent=parent)
    kid = response.key_id
    hmac = response.b64_mac_key
    return kid, hmac