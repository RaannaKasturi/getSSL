

from getGoogleEAB import getGoogleEAB
from getZeroSSLEAB import genZeroSSLEAB


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
    if caserver == "sslcom" and key_type == "rsa":
        return "https://acme.ssl.com/sslcom-dv-rsa"
    elif caserver == "sslcom" and key_type == "ec":
        return "https://acme.ssl.com/sslcom-dv-ecc"
    elif caserver == "letsencrypt_test" and (key_type == "rsa" or key_type == "ec"):
        return "https://acme-staging-v02.api.letsencrypt.org/directory"
    elif caserver == "letsencrypt" and (key_type == "rsa" or key_type == "ec"):
        return "https://acme-v02.api.letsencrypt.org/directory"
    elif caserver == "buypass_test" and (key_type == "rsa" or key_type == "ec"):
        return "https://api.test4.buypass.no/acme/directory"
    elif caserver == "buypass" and (key_type == "rsa" or key_type == "ec"):
        return "https://api.buypass.com/acme/directory"
    elif caserver == "zerossl" and (key_type == "rsa" or key_type == "ec"):
        return "https://acme.zerossl.com/v2/DV90"
    elif caserver == "google_test" and (key_type == "rsa" or key_type == "ec"):
        return "https://dv.acme-v02.test-api.pki.goog/directory"
    elif caserver == "google" and (key_type == "rsa" or key_type == "ec"):
        return "https://dv.acme-v02.api.pki.goog/directory"
    else:
        return "https://acme-staging-v02.api.letsencrypt.org/directory"

def get_kid_hmac(server):
    if server == "sslcom":
        return None, None
    elif server == "letsencrypt_test":
        return None, None
    elif server == "letsencrypt":
        return None, None
    elif server == "buypass_test":
        return None, None
    elif server == "buypass":
        return None, None
    elif server == "zerossl":
        kid, hmac = genZeroSSLEAB()
        return kid, hmac
    elif server == "google_test":
        kid, hmac = getGoogleEAB()
        return kid, hmac
    elif server == "google":
        kid, hmac = getGoogleEAB()
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