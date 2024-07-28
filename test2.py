import josepy as jose
from acme import client, messages
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from genPVTCSR import genPVTCSR
from verificationTokens import verificationTokens

DOMAINS = ['thenayankasturi.eu.org', 'www.thenayankasturi.eu.org', 'dash.thenayankasturi.eu.org']
DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"
EMAIL = "raannakasturi@mail.com"
KEYTYPE = "ec"
KEYCURVE = "ec256"
KEYSIZE = None

def pgclient(directory):
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    account_key = jose.JWKRSA(key=rsa_key)
    net = client.ClientNetwork(account_key, user_agent='simple_acme_dns/v2')
    directory_obj = messages.Directory.from_json(net.get(directory).json())
    acme_client = client.ClientV2(directory_obj, net=net)
    return acme_client

def newAccount(pgclient, directory, email):
    registration = messages.NewRegistration.from_data(email=email, terms_of_service_agreed=True)
    try:
        account = pgclient.new_account(registration)
        return account
    except Exception as e:
        print("Error Registering Account:", e)
        return None, None

def test(domains, email, keyType, keySize=None, keyCurve=None):
    pgkclient = pgclient(DIRECTORY)
    account = newAccount(pgkclient, DIRECTORY, EMAIL)
    if not account:
        print("Failed to register account and generate CSR.")
        exit()
    private_key, csr = genPVTCSR(domains=domains, email=email, keyType=keyType, keyCurve=keyCurve, keySize=keySize)
    verification_tokens = verificationTokens(pgkclient, csr, DIRECTORY)
    print(verification_tokens)

if __name__ == "__main__":
    test(DOMAINS, EMAIL, KEYTYPE, KEYCURVE)
