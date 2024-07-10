import argparse
import json
import sys
import binascii
import time
import hashlib
import re
from urllib.request import urlopen
from acmens import _cmd, _b64, _agree_to, _send_signed_request

__version__ = "0.3.0"

CA_PRD = "https://acme-staging-v02.api.letsencrypt.org"
CA_STG = "https://acme-staging-v02.api.letsencrypt.org"
CA_DIR = None

def get_directory(ca_url):
    global CA_DIR
    if CA_DIR is None:
        CA_DIR = json.loads(urlopen(ca_url + "/directory").read().decode("utf8"))
    return CA_DIR

def get_public_key(account_key):
    print("Decoding private key...")
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
    print("Found public key!")
    return jwk

def poll_until_not(url, pending_statuses, nonce_url, auth, account_key, err_msg):
    result, t0, delay = None, time.time(), 5  # Increase initial delay to 5 seconds
    while result is None or result["status"] in pending_statuses:
        assert time.time() - t0 < 3600, "Polling timeout"  # 1 hour timeout
        print(f"Checking order status: {result['status'] if result else 'None'}")
        time.sleep(delay)
        delay = min(delay * 2, 120)  # Increase the delay, up to a maximum of 120 seconds
        result, _, _ = _send_signed_request(
            url, None, nonce_url, auth, account_key, err_msg
        )
        print(f"Final order status: {result['status']}")
    return result

def get_csr_domains(csr):
    print("Reading csr file...")
    out = _cmd(["openssl", "req", "-in", csr, "-noout", "-text"], err_msg="Error reading CSR")
    domains = set()
    cn = None
    common_name = re.search(r"Subject:.*? CN *= *([^\s,;/]+)", out.decode("utf8"))
    if common_name is not None:
        domains.add(common_name.group(1))
        cn = common_name.group(1).split(".")[0]
    subj_alt_names = re.search(r"X509v3 Subject Alternative Name: \n +([^\n]+)\n", out.decode("utf8"), re.MULTILINE | re.DOTALL)
    if subj_alt_names is not None:
        for san in subj_alt_names.group(1).split(", "):
            if san.startswith("DNS:"):
                dm = san[4:]
                if cn is None and dm.find("*") == -1:
                    cn = dm
                domains.add(dm)
    print("Found domains {}".format(", ".join(domains)))
    return domains, cn

def register_account(ca_url, account_key, email):
    print("Registering {0}...".format(email))
    _agree_to(get_directory(ca_url)["meta"]["termsOfService"])
    reg = {"termsOfServiceAgreed": True}
    nonce_url = get_directory(ca_url)["newNonce"]
    auth = {"jwk": get_public_key(account_key)}
    acct_headers = None
    result, code, acct_headers = _send_signed_request(get_directory(ca_url)["newAccount"], reg, nonce_url, auth, account_key, "Error registering")
    if code == 201:
        print("Registered!")
    else:
        print("Already registered!")
    auth = {"kid": acct_headers["Location"]}
    print("Updating account...")
    ua_result, ua_code, ua_headers = _send_signed_request(acct_headers["Location"], {"contact": ["mailto:{}".format(email)]}, nonce_url, auth, account_key, "Error updating account")
    print("Done")
    return auth

def request_challenges(ca_url, auth, domains, account_key):
    print("Making new order for {0}...".format(", ".join(list(domains))))
    id = {"identifiers": []}
    for domain in domains:
        id["identifiers"].append({"type": "dns", "value": domain})
    order, order_code, order_headers = _send_signed_request(get_directory(ca_url)["newOrder"], id, get_directory(ca_url)["newNonce"], auth, account_key, "Error creating new order")
    return order, order_headers

def dns_challenges(ca_url, auth, order, domain, thumbprint, account_key):
    challenges_info = []
    for auth_url in order["authorizations"]:
        authz_result, authz_code, authz_headers = _send_signed_request(auth_url, None, get_directory(ca_url)["newNonce"], auth, account_key, "Error getting authorization")
        challenge = next((c for c in authz_result["challenges"] if c["type"] == "dns-01" and authz_result["identifier"]["value"] == domain), None)
        if challenge:
            token = challenge["token"]
            key_authorization = "{}.{}".format(token, thumbprint)
            chl_verification = _b64(hashlib.sha256(key_authorization.encode()).digest())
            TXTRec = "_acme-challenge.{}".format(domain)
            TXTValue = chl_verification
            challenges_info.append((TXTRec, TXTValue, challenge["url"]))
    return challenges_info

def dns_verification(ca_url, auth, challenge_url, account_key):
    print("Requesting verification for {}...\n".format(challenge_url))
    verification_result, verification_code, verification_headers = _send_signed_request(challenge_url, {}, get_directory(ca_url)["newNonce"], auth, account_key, "Error submitting challenge")
    if verification_code != 200:
        print(f"Error submitting challenge:\nUrl: {challenge_url}\nData: {json.dumps(verification_result)}\nResponse Code: {verification_code}\nResponse: {verification_result}")
        return False
    print("Challenge verified for {}!\n".format(challenge_url))
    return True

def finalize_order(ca_url, auth, order, order_headers, csr, account_key):
    print("Waiting for challenges to pass...")
    # Polling until the order status is not pending or processing
    order = poll_until_not(order_headers["Location"], ["pending", "processing"], get_directory(ca_url)["newNonce"], auth, account_key, "Error checking order status")
    # Check if the order status is already valid
    if order["status"] == "valid":
        print("Order is already valid. No need to finalize again.")
        return None
    if order["status"] != "ready":
        raise ValueError("Order status is not ready for finalization")
    print("Passed challenges!")
    print("Getting certificate...")
    # Converting CSR to DER format
    csr_der = _cmd(["openssl", "req", "-in", csr, "-outform", "DER"], err_msg="DER Export Error")
    # Finalizing the order
    fnlz_resp, fnlz_code, fnlz_headers = _send_signed_request(order["finalize"], {"csr": _b64(csr_der)}, get_directory(ca_url)["newNonce"], auth, account_key, "Error finalizing order")
    print(f"Finalize response code: {fnlz_code}")
    print(f"Finalize response: {fnlz_resp}")
    if fnlz_code != 200:
        raise ValueError("Failed to finalize the order")
    # Polling until the order status is not pending or processing
    order = poll_until_not(order_headers["Location"], ["pending", "processing"], get_directory(ca_url)["newNonce"], auth, account_key, "Error checking order status after finalization")
    if order["status"] == "valid":
        print("Order finalized successfully!")
    else:
        raise ValueError("Order finalization failed")
    # Getting the certificate
    cert_resp, cert_code, cert_headers = _send_signed_request(order["certificate"], None, get_directory(ca_url)["newNonce"], auth, account_key, "Error getting certificate")
    print(f"Certificate response code: {cert_code}")
    print(f"Certificate response: {cert_resp}")
    if cert_code != 200:
        raise ValueError("Failed to get the certificate")
    print("Received certificate!")
    return cert_resp

def save_cert(data, email):
    certs = data.split('-----BEGIN CERTIFICATE-----\n')[1:]
    for i, cert in enumerate(certs, 1):
        # Preparing certificate content with BEGIN/END headers
        if i == 1:
            file_name = "Certificate.pem"
        elif i == 2:
            file_name = "CA Certificate.pem"
        certFile = f"{email.split('@')[0]/(file_name)}"
        cert_content = f"-----BEGIN CERTIFICATE-----\n{cert.strip()}"
        # Writing to file
        file_name = f"certificate_{i}.pem"
        with open(file_name, 'w') as f:
            f.write(cert_content)
            f.write('\n')
        print(f"Certificate {i} has been written to {file_name}")
        print(f"Certificate saved to {certFile}")

def main():
    parser = argparse.ArgumentParser(description='ACME client script.')
    parser.add_argument('--account-key', required=True, help='Path to the account private key file.')
    parser.add_argument('--csr', required=True, help='Path to the certificate signing request file.')
    parser.add_argument('--email', required=True, help='Email address for registration.')
    parser.add_argument('--ca', default=CA_STG, help='CA URL, default is LetsEncrypt staging.')
    parser.add_argument('--dns', action='store_true', help='Use DNS-01 challenge instead of HTTP-01.')
    args = parser.parse_args()

    account_key = args.account_key
    csr = args.csr
    email = args.email
    ca_url = args.ca
    use_dns = args.dns

    domains, common_name = get_csr_domains(csr)
    auth = register_account(ca_url, account_key, email)
    order, order_headers = request_challenges(ca_url, auth, domains, account_key)

    if use_dns:
        thumbprint = _b64(hashlib.sha256(json.dumps(get_public_key(account_key), sort_keys=True, separators=(',', ':')).encode()).digest())
        challenges_info = []
        for domain in domains:
            challenges = dns_challenges(ca_url, auth, order, domain, thumbprint, account_key)
            challenges_info.extend(challenges)

        for TXTRec, TXTValue, challenge_url in challenges_info:
            print(f"Challenge for {TXTRec} is {TXTValue}")
            print(f"Please update your DNS for '{TXTRec}' to have the following TXT record:")
            print(f"{TXTRec}    IN    TXT ( \"{TXTValue}\" )\n")

            input("Press Enter when the TXT record is updated on the DNS...")

        for TXTRec, TXTValue, challenge_url in challenges_info:
            success = dns_verification(ca_url, auth, challenge_url, account_key)
            if not success:
                print("DNS verification failed. Exiting.")
                return

    else:
        raise ValueError("Only DNS challenge supported in this script")

    cert = finalize_order(ca_url, auth, order, order_headers, csr, account_key)
    if cert:
        save_cert(cert, email)

if __name__ == "__main__":
    main()
    #python3 test.py --account-key raannakasturi/tempPrivate.pem --csr raannakasturi/domain.csr --email raannakasturi@gmail.com --dns
