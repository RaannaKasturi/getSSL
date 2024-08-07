

from getGoogleEAB import gen_google_eab
from getZeroSSLEAB import gen_zero_ssl_eab


def get_domains(i_domains):
    domains = []
    for domain in i_domains.split(","):
        domain = domain.strip()
        domains.append(domain)
    return domains

def extract_subdomains(domains):
    exchange = min(domains, key=len)
    return exchange

def get_ca_server(caserver, key_type):
    DEFAULT_LET_ENCRYPT_URL = "https://acme-v02.api.letsencrypt.org/directory"
    urls = {
        "SSL.com": {
            "rsa": "https://acme.ssl.com/sslcom-dv-rsa",
            "ec": "https://acme.ssl.com/sslcom-dv-ecc"
        },
        "Let's Encrypt (Testing)": "https://acme-staging-v02.api.letsencrypt.org/directory",
        "Let's Encrypt": DEFAULT_LET_ENCRYPT_URL,
        "Buypass (Testing)": "https://api.test4.buypass.no/acme/directory",
        "Buypass": "https://api.Buypass.com/acme/directory",
        "ZeroSSL": "https://acme.zerossl.com/v2/DV90",
        "Google (Testing)": "https://dv.acme-v02.test-api.pki.goog/directory",
        "Google": "https://dv.acme-v02.api.pki.goog/directory"
    }
    if caserver in urls:
        if isinstance(urls[caserver], dict):
            return urls[caserver].get(key_type, DEFAULT_LET_ENCRYPT_URL)
        else:
            return urls[caserver]
    return DEFAULT_LET_ENCRYPT_URL

def get_kid_hmac(server):
    if server == "SSL.com":
        return None, None
    elif server == "Let's Encrypt (Testing)":
        return None, None
    elif server == "Let's Encrypt":
        return None, None
    elif server == "Buypass (Testing)":
        return None, None
    elif server == "Buypass":
        return None, None
    elif server == "ZeroSSL":
        kid, hmac = gen_zero_ssl_eab()
        return kid, hmac
    elif server == "Google (Testing)":
        kid, hmac = gen_google_eab()
        return kid, hmac
    elif server == "Google":
        kid, hmac = gen_google_eab()
        return kid, hmac
    else:
        return None, None

def write_file(filename, data):
    try:
        with open(filename, 'wb') as f:
            f.write(data)
        print(filename, " successfully written")
    except Exception as e:
        print("Error writing file: ", filename)
        print(e)