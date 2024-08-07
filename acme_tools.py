import sys
import josepy as jose
from acme import messages, jose
from acme import client, messages
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

def pg_client(directory, key_type="rsa", key_size=None, key_curve=None):
    try:
        if key_type.lower() == "rsa":
            if key_size == "" or key_size ==  None:
                key_size = 4096
            rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
            account_key = jose.JWKRSA(key=rsa_key)
            net = client.ClientNetwork(account_key, user_agent='project-gatekeeper/v1.5')
            directory_obj = messages.Directory.from_json(net.get(directory).json())
            acme_client = client.ClientV2(directory_obj, net=net)
            return acme_client
        elif key_type.lower() == "ec":
            if key_curve == "" or key_curve == None:
                key_curve = "ec256"
            if key_curve == 'SECP256R1' or key_curve == 'ec256':
                ec_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
                algo=jose.ES256
            elif key_curve == 'SECP384R1' or key_curve == 'ec384':
                ec_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
                algo=jose.ES384
            account_key = jose.JWKEC(key=ec_key)
            net = client.ClientNetwork(account_key, alg=algo, user_agent='project-gatekeeper/v2')
            response = net.get(directory)
            directory_obj = messages.Directory.from_json(response.json())
            acme_client = client.ClientV2(directory_obj, net=net)
            return acme_client
        else:
            print("Invalid key_type")
            sys.exit()
    except:
        print("Error in initialization")
        sys.exit()

def new_account(pgclient, email, kid=None, hmac=None):
    external_account_binding = None
    if kid and hmac:
        if isinstance(hmac, bytes):
            hmac = hmac.decode('utf-8')
        if not isinstance(hmac, str):
            print("Error: HMAC is not a string after decoding.")
            return False
        try:
            hmac_bytes = jose.b64.b64decode(hmac)
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