from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
import OpenSSL
import error

def savefile(filename, data):
    with open(filename, 'wb') as f:
        f.write(data)
    return filename

def generate_private_key(key_type):
    # Generate a EC256 private key
    if key_type == 'ec256':
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        private_key = key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption())
    # Generate a EC384 private key
    elif key_type == 'ec384':
        key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        private_key = key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        )
    # Generate a RSA2048 private key
    elif key_type == 'rsa2048':
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        private_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
    # Generate a RSA4096 private key
    elif key_type == 'rsa4096':
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 4096)
        private_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
    # Otherwise, the requested key type is not supported. Throw an error
    else:
        options = ['ec256', 'ec384', 'rsa2048', 'rsa4096']
        msg = f"Invalid private key rtype '{key_type}'. Options {options}"
        raise error.InvalidKeyType(msg)
    return private_key

def genCSR(private_key, common_name, country, state, locality, organization, organization_unit, email, domains):
    csr = OpenSSL.crypto.X509Req()
    csr.get_subject().CN = common_name
    csr.get_subject().C = country
    csr.get_subject().ST = state
    csr.get_subject().L = locality
    csr.get_subject().O = organization
    csr.get_subject().OU = organization_unit
    csr.get_subject().emailAddress = email
    with open(private_key, 'rb') as f:
        data = f.read()
        pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, data)
    csr.set_pubkey(pkey)
    extensions = []
    for domain in domains:
        ext = OpenSSL.crypto.X509Extension(b'subjectAltName', critical=False, value=b'DNS:' + domain.encode())
        extensions.append(ext)
    csr.add_extensions(extensions)
    csr.sign(pkey, "sha256")
    csrdata = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr)
    return csrdata

def genPrivCSR(key_type, privFile, csrFile, common_name, country, state, locality, organization, organization_unit, email, domains):
    private_key = savefile(privFile, generate_private_key(key_type))
    csr = savefile(csrFile, (genCSR(private_key, common_name, country, state, locality, organization, organization_unit, email, domains)))
    return private_key, csr

