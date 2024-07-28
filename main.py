import os
import sys
import josepy as jose

from dotenv import load_dotenv
from acme import client, messages
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from genPVTCSR import genPVTCSR
from verificationTokens import getTokens, verifyTokens

def pgclient(directory, keyType="rsa", keySize=None, keyCurve=None):
    try:
        if keyType.lower() == "rsa":
            if keySize == "" or keySize ==  None:
                keySize = 4096
            rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=keySize, backend=default_backend())
            account_key = jose.JWKRSA(key=rsa_key)
            net = client.ClientNetwork(account_key, user_agent='project-gatekeeper/v1.5')
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
        else:
            print("Invalid keyType")
            sys.exit()
    except:
        print("Error in initialization")
        sys.exit()

from acme import messages, jose

def newAccount(pgclient, email, kid=None, hmac=None):
    external_account_binding = None
    if kid and hmac:
        print(f"Original hmac: {hmac}, Type: {type(hmac)}")
        if isinstance(hmac, bytes):
            hmac = hmac.decode('utf-8')
            print(f"Decoded hmac: {hmac}, Type: {type(hmac)}")
        if not isinstance(hmac, str):
            print("Error: HMAC is not a string after decoding.")
            return False
        try:
            hmac_bytes = jose.b64.b64decode(hmac)
            print(f"HMAC bytes: {hmac_bytes}, Type: {type(hmac_bytes)}")
            hmac_key = jose.jwk.JWKOct(key=hmac_bytes)
        except Exception as e:
            print(f"Error decoding HMAC key: {e}")
            return False
        hmac_key_b64 = jose.b64.b64encode(hmac_bytes).decode('utf-8')
        external_account_binding = messages.ExternalAccountBinding.from_data(
            account_public_key=pgclient.net.key,
            kid=kid,
            hmac_key=hmac_key_b64,
            directory=pgclient.directory
        )
    registration = messages.NewRegistration.from_data(
        email=email,
        terms_of_service_agreed=True,
        external_account_binding=external_account_binding
    )
    try:
        account = pgclient.new_account(registration)
        return account
    except Exception as e:
        print(f"Error creating account: {e}")
        return False

def write(filename, data):
    try:
        with open(filename, 'wb') as f:
            f.write(data)
        print(filename, " successfully written")
    except Exception as e:
        print("Error writing file: ", filename)
        print(e)

def test(domains, email, keyType, keySize=None, keyCurve=None, kid=None, hmac=None):
    pgkclient = pgclient(DIRECTORY, keyType=keyType, keySize=keySize, keyCurve=keyCurve)
    if pgkclient is None:
        exit()
    account = newAccount(pgkclient, EMAIL, kid=kid, hmac=hmac)
    if not account:
        exit()
    private_key, csr = genPVTCSR(domains=domains, email=email, keyType=keyType, keyCurve=keyCurve, keySize=keySize)
    verification_tokens, challs, order = getTokens(pgkclient, csr, DIRECTORY)
    print(verification_tokens)
    while True:
        proceed = input("Proceed? y/n")
        if proceed.lower() == 'y':
            break
        elif proceed.lower() == 'n':
            continue
    cert = verifyTokens(pgkclient, challs, order)
    write("private.pem", private_key)
    write("domain.csr", csr)
    write("cert.pem", cert)

if __name__ == "__main__":
    load_dotenv()
    DOMAINS = ['thenayankasturi.eu.org', 'www.thenayankasturi.eu.org', 'dash.thenayankasturi.eu.org']
    DIRECTORY = "https://dv.acme-v02.test-api.pki.goog/directory" #"https://acme-staging-v02.api.letsencrypt.org/directory"
    EMAIL = "raannakasturi@mail.com"
    KEYTYPE = "ec"
    KEYCURVE = "ec256"
    KEYSIZE = None
    KID = os.getenv("KID")
    HMAC = os.getenv('HMAC')
    print(KID)
    print(HMAC)
    sys.exit(1)
    test(domains=DOMAINS, email=EMAIL, keyType=KEYTYPE, keySize=KEYSIZE,keyCurve=KEYCURVE, kid=KID, hmac=HMAC)
