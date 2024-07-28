import hashlib
import json
import josepy as jose
import collections

from tools import _b64Encode, _encodeInt
from acme import client, messages
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def genAccountKey(keyType, keySize=None, keyCurve=None):
    try:
        if keyType.lower() == "rsa" and keySize is not None:
            accountKey = rsa.generate_private_key(public_exponent=65537, key_size=keySize, backend=default_backend())
        elif keyType.lower() == "ecc" and keyCurve is not None:
            if keyCurve.upper() == "SECP256R1":
                curve = ec.SECP256R1()
            elif keyCurve.upper() == "SECP384R1":
                curve = ec.SECP384R1()
            elif keyCurve.upper() == "SECP521R1":
                curve = ec.SECP521R1()
            else:
                raise ValueError("Unsupported ECC curve.")
            accountKey = ec.generate_private_key(curve=curve, backend=default_backend())
        else:
            accountKey = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    except:
        accountKey = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    return accountKey

def genJWK(accountKey):
    pubKey = accountKey.public_key()
    pubNum = pubKey.public_numbers()
    jwk = collections.OrderedDict()
    if hasattr(accountKey, "curve"):
            jwk["crv"] = str("P-{}").format(512 if pubKey.curve.key_size == 521 else pubKey.curve.key_size)
            jwk["kty"] = 'EC'
            jwk["x"] = _b64Encode(_encodeInt(pubNum.x, pubKey.curve.key_size))
            jwk["y"] = _b64Encode(_encodeInt(pubNum.y, pubKey.curve.key_size))
    else:
        jwk["e"] = _b64Encode(_encodeInt(pubNum.e, pubKey.key_size))
        jwk["kty"] = 'RSA'
        jwk["n"] = _b64Encode(_encodeInt(pubNum.n, pubKey.key_size))
    jwkHash = _b64Encode(hashlib.sha256(json.dumps(jwk, separators=(",", ":"), ensure_ascii=False).encode()).digest())
    return jwk, jwkHash

def createAccount(accountKey, directory, email):
    net = client.ClientNetwork(key=accountKey, alg=jose.ES256, user_agent='simple_acme_dns/v2')
    directory_obj = messages.Directory.from_json(net.get(directory).json())
    acme_client = client.ClientV2(directory_obj, net=net)
    registration = messages.NewRegistration.from_data(email=email, terms_of_service_agreed=True)
    account = acme_client.new_account(registration)
    return account

def main():
    keyType = "ecc"
    keyCurve = "SECP256R1"
    directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
    email = "raannakasturi@gmail.com"
    accountKey = genAccountKey(keyType, keyCurve=keyCurve) # 2048, 4096, SECP256R1, SECP384R1, SECP521R1(Not Supported)
    privateKey = accountKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    jwk, jwkHash = genJWK(accountKey)
    account = createAccount(accountKey, directory, email)
    print(account)

