from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from typing import List, Tuple

def gen_pvt(key_type: str, key_size: int = None, key_curve: str = None) -> bytes:
    if key_type.lower() == "ec":
        if key_curve == 'SECP256R1' or key_curve == 'ec256':
            key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        elif key_curve == 'SECP384R1' or key_curve == 'ec384':
            key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        else:
            key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        private_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    elif key_type.lower() == "rsa":
        if key_size not in [2048, 4096]:
            key_size = 4096
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
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

def gen_csr(private_key: bytes, domains: List[str], email: str, common_name: str = None, country: str = None,
           state: str = None, locality: str = None, organization: str = None, organization_unit: str = None) -> bytes:
    
    ssl_domains = [x509.DNSName(domain.strip()) for domain in domains]
    private_key_obj = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    try:
        if email.split("@")[1] in ["demo.com", "example.com"] or email.count("@") > 1 or email.count(".") < 1 or email is None:
            print("Invalid email address")
            email = f"admin@{domains[0]}"
    except Exception as e:
        print(f"Error in email address: {e}")
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
        x509.SubjectAlternativeName(ssl_domains),
        critical=False,
    )
    csr = builder.sign(private_key_obj, hashes.SHA256(), default_backend())
    return csr.public_bytes(serialization.Encoding.PEM)

def gen_pvt_csr(domains: List[str], key_type: str, key_size: int = None, key_curve: str = None, email: str = None,
              common_name: str = None, country: str = None, state: str = None, locality: str = None,
              organization: str = None, organization_unit: str = None) -> Tuple[bytes, bytes]:
    if key_type.lower() == "rsa":
        private_key = gen_pvt(key_type, key_size)
    else:
        private_key = gen_pvt(key_type, key_curve)
    csr = gen_csr(private_key, domains, email, common_name, country, state, locality, organization, organization_unit)
    return private_key, csr
