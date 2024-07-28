from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from typing import List, Tuple

def genPVTKey(keyType: str, keySize: int = None, keyCurve: str = None) -> bytes:
    if keyType.lower() == "ec":
        if keyCurve == 'SECP256R1' or keyCurve == 'ec256':
            key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        elif keyCurve == 'SECP384R1' or keyCurve == 'ec384':
            key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        else:
            key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        private_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    elif keyType.lower() == "rsa":
        if keySize not in [2048, 4096]:
            keySize = 4096
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=keySize,
            backend=default_backend()
        )
        private_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        raise ValueError("Unsupported key type or parameters")
    return private_key

def genCSR(private_key: bytes, domains: List[str], email: str, common_name: str = None, country: str = None,
           state: str = None, locality: str = None, organization: str = None, organization_unit: str = None) -> bytes:
    
    sslDomains = [x509.DNSName(domain.strip()) for domain in domains]
    private_key_obj = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    try:
        if email.split("@")[1] in ["demo.com", "example.com"] or email.count("@") > 1 or email.count(".") < 1 or email is None:
            print("Invalid email address")
            email = f"admin@{domains[0]}"
    except:
        email = f"admin@{domains[0]}"
    country: str = country or "IN"
    state: str = state or "Maharashtra"
    locality: str = locality or "Mumbai"
    organization_unit: str = organization_unit or "IT Department"
    common_name: str = common_name or domains[0]
    organization: str = organization or common_name.split(".")[0]
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organization_unit),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject)
    builder = builder.add_extension(
        x509.SubjectAlternativeName(sslDomains),
        critical=False,
    )
    csr = builder.sign(private_key_obj, hashes.SHA256(), default_backend())
    return csr.public_bytes(serialization.Encoding.PEM)

def genPVTCSR(domains: List[str], keyType: str, keySize: int = None, keyCurve: str = None, email: str = None,
              commonName: str = None, country: str = None, state: str = None, locality: str = None,
              organization: str = None, organizationUnit: str = None) -> Tuple[bytes, bytes]:
    if keyType.lower() == "rsa":
        private_key = genPVTKey(keyType, keySize)
    else:
        private_key = genPVTKey(keyType, keyCurve)
    csr = genCSR(private_key, domains, email, commonName, country, state, locality, organization, organizationUnit)
    return private_key, csr
