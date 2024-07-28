import sys
import josepy as jose
from acme import client, messages
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from genPVTCSR import genPVTCSR
from verificationTokens import verificationTokens


DOMAINS = ['thenayankasturi.eu.org', 'www.thenayankasturi.eu.org', 'dash.thenayankasturi.eu.org']
DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"
EMAIL = "raannakasturi@mail.com"
KEYTYPE = "rsa"
KEYCURVE = "4096"
KEYSIZE = None

def pgclient(directory, keyType="rsa", keySize=None, keyCurve=None):
    try:
        if keyType.lower() == "rsa":
            if keySize == "" or keySize ==  None:
                keySize = 4096
            rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=keySize, backend=default_backend())
            account_key = jose.JWKRSA(key=rsa_key)
            net = client.ClientNetwork(account_key, user_agent='simple_acme_dns/v2')
            directory_obj = messages.Directory.from_json(net.get(directory).json())
            acme_client = client.ClientV2(directory_obj, net=net)
            return acme_client
        elif keyType.lower() == "ec":
            if keyCurve == "" or keyCurve == None:
                keyCurve = "ec256"
            if keyCurve == 'SECP256R1' or keyCurve == 'ec256':
                ec_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
                algo=jose.ES256
            elif keyCurve == 'SECP384R1' or keyCurve == 'ec384':
                ec_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
                algo=jose.ES384
            account_key = jose.JWKEC(key=ec_key)
            net = client.ClientNetwork(account_key, alg=algo, user_agent='project-gatekeeper/v2')
            response = net.get(directory)
            directory_obj = messages.Directory.from_json(response.json())
            acme_client = client.ClientV2(directory_obj, net=net)
            return acme_client
    except:
        print("Error in initialization")
        sys.exit()

def newAccount(pgclient, email):
    registration = messages.NewRegistration.from_data(email=email, terms_of_service_agreed=True)
    try:
        account = pgclient.new_account(registration)
        return account
    except Exception as e:
        return False

def test(domains, email, keyType, keySize=None, keyCurve=None):
    pgkclient = pgclient(DIRECTORY, keyType=keyType, keySize=keySize, keyCurve=keyCurve)
    if pgkclient is None:
        exit()
    account = newAccount(pgkclient, EMAIL)
    if not account:
        exit()
    private_key, csr = genPVTCSR(domains=domains, email=email, keyType=keyType, keyCurve=keyCurve, keySize=keySize)
    verification_tokens = verificationTokens(pgkclient, csr, DIRECTORY)
    print(verification_tokens)

if __name__ == "__main__":
    test(DOMAINS, EMAIL, KEYTYPE, KEYCURVE)
