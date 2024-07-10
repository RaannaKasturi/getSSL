import argparse
import subprocess
import json
import urllib.request
import sys
import base64
import binascii
import time
import hashlib
import re
from urllib.request import urlopen
from urllib.error import URLError
from acmens import _cmd, _b64, _agree_to, _send_signed_request, _poll_until_not

__version__ = "0.3.0"

CA_PRD = "https://acme-v02.api.letsencrypt.org"
CA_STG = "https://acme-staging-v02.api.letsencrypt.org"
CA_DIR = None

def get_directory(ca_url):
    global CA_DIR
    if CA_DIR is None:
        CA_DIR = json.loads(urlopen(ca_url + "/directory").read().decode("utf8"))
    return CA_DIR

def get_public_key(account_key):
    sys.stderr.write("Reading pubkey file...\n")
    out = _cmd(["openssl", "rsa", "-in", account_key, "-noout", "-text"], err_msg="Error reading account public key")
    pub_hex, pub_exp = re.search(r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)", out.decode("utf8"), re.MULTILINE | re.DOTALL).groups()
    pub_mod = binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex))
    pub_mod64 = _b64(pub_mod)
    pub_exp = int(pub_exp)
    pub_exp = "{0:x}".format(pub_exp)
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    pub_exp = binascii.unhexlify(pub_exp)
    pub_exp64 = _b64(pub_exp)
    jwk = {"e": pub_exp64, "kty": "RSA", "n": pub_mod64}
    sys.stderr.write("Found public key!\n")
    return jwk

def poll_until_not(url, pending_statuses, nonce_url, auth, account_key, err_msg):
    """Poll until status is not in pending_statuses"""
    result, t0, delay = None, time.time(), 2
    while result is None or result["status"] in pending_statuses:
        assert time.time() - t0 < 3600, "Polling timeout"  # 1 hour timeout
        sys.stderr.write(f"Checking order status: {result['status'] if result else 'None'}\n")
        time.sleep(delay)
        delay = min(delay +1, 60)  # Increase the delay, up to a maximum of 60 seconds
        result, _, _ = _send_signed_request(
            url, None, nonce_url, auth, account_key, err_msg
        )
    sys.stderr.write(f"Final order status: {result['status']}\n")
    return result

def get_csr_domains(csr):
    sys.stderr.write("Reading csr file...\n")
    out = _cmd(["openssl", "req", "-in", csr, "-noout", "-text"], err_msg="Error reading CSR")
    domains = set()
    cn = None
    common_name = re.search(r"Subject:.*? CN *= *([^\s,;/]+)", out.decode("utf8"))
    if common_name is not None:
        domains.add(common_name.group(1))
        cn = common_name.group(1)
    subj_alt_names = re.search("X509v3 Subject Alternative Name: \n +([^\n]+)\n", out.decode("utf8"), re.MULTILINE | re.DOTALL)
    if subj_alt_names is not None:
        for san in subj_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                dm = san[4:]
                if cn is None and dm.find("*") == -1:
                    cn = dm
                domains.add(dm)
    sys.stderr.write("Found domains {}\n".format(", ".join(domains)))
    return domains, cn

def register_account(ca_url, account_key, email):
    sys.stderr.write("Registering {0}...\n".format(email))
    _agree_to(get_directory(ca_url)["meta"]["termsOfService"])
    reg = {"termsOfServiceAgreed": True}
    nonce_url = get_directory(ca_url)["newNonce"]
    auth = {"jwk": get_public_key(account_key)}
    acct_headers = None
    result, code, acct_headers = _send_signed_request(get_directory(ca_url)["newAccount"], reg, nonce_url, auth, account_key, "Error registering")
    if code == 201:
        sys.stderr.write("Registered!\n")
    else:
        sys.stderr.write("Already registered!\n")
    auth = {"kid": acct_headers["Location"]}
    sys.stderr.write("Updating account...")
    ua_result, ua_code, ua_headers = _send_signed_request(acct_headers["Location"], {"contact": ["mailto:{}".format(email)]}, nonce_url, auth, account_key, "Error updating account")
    sys.stderr.write("Done\n")
    return auth

def request_challenges(ca_url, auth, domains, account_key):
    sys.stderr.write("Making new order for {0}...\n".format(", ".join(list(domains))))
    id = {"identifiers": []}
    for domain in domains:
        id["identifiers"].append({"type": "dns", "value": domain})
    order, order_code, order_headers = _send_signed_request(get_directory(ca_url)["newOrder"], id, get_directory(ca_url)["newNonce"], auth, account_key, "Error creating new order")
    return order, order_headers

def do_dns_challenge(ca_url, auth, order, domain, thumbprint, account_key):
    sys.stderr.write("Requesting challenges...\n")
    chl_result, chl_code, chl_headers = _send_signed_request(order["authorizations"][0], None, get_directory(ca_url)["newNonce"], auth, account_key, "Error getting challenges")
    challenge = None
    for authz in order["authorizations"]:
        authz_result, authz_code, authz_headers = _send_signed_request(authz, None, get_directory(ca_url)["newNonce"], auth, account_key, "Error getting authorization")
        challenge = next((c for c in authz_result["challenges"] if c["type"] == "dns-01" and authz_result["identifier"]["value"] == domain), None)
        if challenge:
            break
    
    if not challenge:
        sys.stderr.write(f"No challenge found for domain {domain}. Skipping...\n")
        return order
    
    token = challenge["token"]
    key_authorization = "{}.{}".format(token, thumbprint)
    chl_verification = _b64(hashlib.sha256(key_authorization.encode()).digest())
    sys.stderr.write("Please update your DNS for '{0}' to have the following TXT record:\n\n--------------\n_acme-challenge    IN    TXT ( \"{1}\" )\n--------------\n\nPress Enter when the TXT record is updated on the DNS...\n".format(domain, chl_verification))
    input()
    sys.stderr.write("Requesting verification for {}...\n".format(domain))
    _send_signed_request(challenge["url"], {}, get_directory(ca_url)["newNonce"], auth, account_key, "Error submitting challenge")
    sys.stderr.write("{} verified!\n".format(domain))
    sys.stderr.write("You can remove the _acme-challenge DNS TXT record now.\n")
    print("------------------------------------------------------------")
    print("Order status: {}".format(order["status"]))
    print("------------------------------------------------------------")
    return order

def finalize_order(ca_url, auth, order, order_headers, csr, account_key):
    sys.stderr.write("Waiting for challenges to pass...\n")
    order = poll_until_not(order_headers["Location"], ["pending", "processing"], get_directory(ca_url)["newNonce"], auth, account_key, "Error checking order status")
    print(order)
    if order["status"] == "ready":
        sys.stderr.write("Passed challenges!\n")
    else:
        raise ValueError("Challenges did not pass")
    sys.stderr.write("Getting certificate...\n")
    csr_der = _cmd(["openssl", "req", "-in", csr, "-outform", "DER"], err_msg="DER Export Error")
    fnlz_resp, fnlz_code, fnlz_headers = _send_signed_request(order["finalize"], {"csr": _b64(csr_der)}, get_directory(ca_url)["newNonce"], auth, account_key, "Error finalizing order")
    print("------------------------------------------------------------")
    #print(_send_signed_request(order['finalize']))
    print("------------------------------------------------------------")
    signed_pem, _, _ = _send_signed_request(order["finalize"], None, get_directory(ca_url)["newNonce"], auth, account_key, "Error getting certificate")
    sys.stderr.write("Received certificate!\n")
    return signed_pem

def main():
    ca_url = CA_STG
    account_key = "private.pem"
    csr = "domain.csr"
    email = "raannakasturi@gmail.com"
    challenge_type = "dns"
    
    jwk = get_public_key(account_key)
    accountkey_json = json.dumps(jwk, sort_keys=True, separators=(",", ":"))
    thumbprint = _b64(hashlib.sha256(accountkey_json.encode()).digest())
    
    auth = register_account(ca_url, account_key, email)
    
    domains, cn = get_csr_domains(csr)
    order, order_headers = request_challenges(ca_url, auth, domains, account_key)
    
    for domain in domains:
        order = do_dns_challenge(ca_url, auth, order, domain, thumbprint, account_key)
    signed_crt = finalize_order(ca_url, auth, order, order_headers, csr, account_key)
    
    sys.stdout.write(signed_crt)

if __name__ == "__main__":
    main()