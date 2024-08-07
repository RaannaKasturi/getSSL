import os
from dotenv import load_dotenv
from google.oauth2 import service_account
from google.cloud.security.publicca import PublicCertificateAuthorityServiceClient as productionclient
from google.cloud.security.publicca_v1beta1 import PublicCertificateAuthorityServiceClient as testingclient

def gen_google_eab_data():
    load_dotenv()
    data = {
        "type": "service_account",
        "project_id": os.getenv("PROJECT_ID"),
        "private_key_id": os.getenv("PRIVATE_KEY_ID"),
        "private_key": os.getenv("PRIVATE_KEY"),
        "client_email": os.getenv("CLIENT_EMAIL"),
        "client_id": os.getenv("CLIENT_ID"),
        "auth_uri": os.getenv("AUTH_URI"),
        "token_uri": os.getenv("TOKEN_URI"),
        "auth_provider_x509_cert_url": os.getenv("AUTH_PROVIDER_X509_CERT_URL"),
        "client_x509_cert_url": os.getenv("CLIENT_X509_CERT_URL"),
        "universe_domain": os.getenv("UNIVERSE_DOMAIN")
    }
    return data

def gen_google_eab(test:bool):
    service_account_info = gen_google_eab_data()
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