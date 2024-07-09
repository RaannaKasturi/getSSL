import os
import logging
import re
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from OpenSSL import crypto

class InvalidKeyType(Exception):
    pass

def savefile(filename, data):
    with open(filename, 'wb') as f:
        f.write(data)
    return filename

def generate_private_key(key_type):
    key = None
    private_key = None
    public_key = None

    if key_type == 'ec256':
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    elif key_type == 'ec384':
        key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    elif key_type in ['rsa2048', 'rsa4096']:
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, int(key_type[3:]))
    
    if isinstance(key, ec.EllipticCurvePrivateKey):
        private_key = key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption())
        public_key = key.public_key().public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo)
    else:
        private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
        public_key = crypto.dump_publickey(crypto.FILETYPE_PEM, key)

    if private_key is None or public_key is None:
        raise InvalidKeyType(f"Invalid private key type '{key_type}'. Options are ['ec256', 'ec384', 'rsa2048', 'rsa4096']")
    
    return private_key, public_key

def genCSR(private_key, email, domains, common_name, country, state, locality, organization, organization_unit):
    sslDomains = [x509.DNSName(domain.strip()) for domain in domains.split(',')]
    with open(private_key, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS, email),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, organization_unit),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
    ])
    
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject)
    builder = builder.add_extension(
        x509.SubjectAlternativeName(sslDomains),
        critical=False,
    )
    csr = builder.sign(private_key, hashes.SHA256(), default_backend())
    return csr.public_bytes(serialization.Encoding.PEM)

def verifyPrivCSR(privdata, csrdata):
    try:
        req = crypto.load_certificate_request(crypto.FILETYPE_PEM, csrdata)
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, privdata)
        req.verify(pkey)
        return True
    except crypto.Error:
        print("Private key and CSR verification failed", exc_info=True)
        return False

def genPrivCSR(email, domains, key_type="rsa4096", common_name="", country="IN", state="Maharashtra", locality="Mumbai", organization="", organization_unit="IT"):
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        print("Invalid email address")
        return None, None
    
    domains_list = [domain.strip() for domain in domains.split(",")]
    if any(domain.startswith("*.") for domain in domains_list):
        print("Wildcard domains are not supported")
        return None, None

    if not key_type.lower() in ['ec256', 'ec384', 'rsa2048', 'rsa4096']:
        print(f"Invalid private key type '{key_type}'. Options are: ['ec256', 'ec384', 'rsa2048', 'rsa4096']")
        return None, None

    common_name = common_name or domains_list[0]
    organization = organization or common_name.split(".")[0]
    
    path = email.split("@")[0]
    os.makedirs(path, exist_ok=True)

    privdata, pubdata = generate_private_key(key_type.lower())
    savefile(f"{path}/private.pem", privdata)
    savefile(f"{path}/public.pem", pubdata)
    
    csrdata = genCSR(f"{path}/private.pem", email, domains, common_name, country, state, locality, organization, organization_unit)
    savefile(f"{path}/domain.csr", csrdata)
    
    if verifyPrivCSR(privdata, csrdata):
        print("Private key and CSR are verified")
        return privdata, csrdata
    else:
        print("Error in generating Private Key and CSR. Please try again.")
        return None, None

if __name__ == "__main__":
    email = "raannakasturi@gmail.com"
    domains = "thenayankasturi.eu.org, www.thenayankasturi.eu.org, mail.thenayankasturi.eu.org, dash.thenayankasturi.eu.org"
    genPrivCSR(email, domains, key_type="rsa4096")
