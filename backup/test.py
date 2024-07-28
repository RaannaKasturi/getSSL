from acme import client, messages, crypto_util
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization  # Add this line to import the serialization module
import josepy as jose
from  app import genAccountKey

_email = "raannakasturi@gmail.com"
directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
keyType="ECC"
keyCurve="SECP256R1"
domains =  ['thenayankasturi.eu.org, *.thenayankasturi.eu.org']



rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
account_key = jose.JWKRSA(key=rsa_key)
# Initialize our ACME client object
net = client.ClientNetwork(account_key, user_agent='simple_acme_dns/v2')
directory_obj = messages.Directory.from_json(net.get(directory).json())
acme_client = client.ClientV2(directory_obj, net=net)
# Complete registration
registration = messages.NewRegistration.from_data(email=_email, terms_of_service_agreed=True)
account = acme_client.new_account(registration)
print("account created")
accountKey = genAccountKey(keyType, keyCurve=keyCurve)
privateKey = accountKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
csr = crypto_util.make_csr(privateKey, domains)
print(csr)