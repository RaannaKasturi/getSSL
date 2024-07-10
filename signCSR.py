import argparse
import urllib.request
import base64
import json
import subprocess
import sys
import binascii
import time
import hashlib
import re
from urllib.error import URLError
from urllib.request import urlopen

__version__ = "0.3.0"

CA_PRD = "https://acme-staging-v02.api.letsencrypt.org"
CA_STG = "https://acme-staging-v02.api.letsencrypt.org"
CA_DIR = None

def get_directory(ca_url):
    global CA_DIR
    if CA_DIR is None:
        CA_DIR = json.loads(urlopen(ca_url + "/directory").read().decode("utf8"))
    return CA_DIR

def cmd(cmd_list, stdin=None, cmd_input=None, err_msg="Command Line Error"):
    "Runs external commands"
    proc = subprocess.Popen(
        cmd_list, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    out, err = proc.communicate(cmd_input)
    if proc.returncode != 0:
        sys.stderr.write("{0}: {1}\n".format(err_msg, err.decode()))
        sys.exit(1)
    return out

def b64(b):
    if type(b) is str:
        b = b.encode()
    return base64.urlsafeb64encode(b).decode().replace("=", "")

def do_request(url, data=None, err_msg="Error"):
    try:
        resp = urllib.request.urlopen(
            urllib.request.Request(
                url,
                data=data,
                headers={
                    "Content-Type": "application/jose+json",
                    "User-Agent": "acmens",
                },
            )
        )
        resp_data, code, headers = (
            resp.read().decode("utf8"),
            resp.getcode(),
            resp.headers,
        )
    except URLError as e:
        resp_data = e.read().decode("utf8") if hasattr(e, "read") else str(e)
        code, headers = getattr(e, "code", None), {}
    try:
        resp_data = json.loads(resp_data)  # try to parse json results
    except ValueError:
        pass  # resp_data is not a JSON string; that's fine
    return resp_data, code, headers

def _mk_signed_req_body(url, payload, nonce, auth, account_key):
    if len(nonce) < 1:
        sys.stderr.write("_mk_signed_req_body: nonce invalid: {}".format(nonce))
        sys.exit(1)

    payload64 = "" if payload is None else b64(json.dumps(payload).encode("utf8"))
    protected = {"url": url, "alg": "RS256", "nonce": nonce}
    protected.update(auth)
    protected64 = b64(json.dumps(protected).encode("utf8"))
    protected_input = "{0}.{1}".format(protected64, payload64).encode("utf8")
    out = cmd(
        ["openssl", "dgst", "-sha256", "-sign", account_key],
        stdin=subprocess.PIPE,
        cmd_input=protected_input,
        err_msg="OpenSSL Error",
    )
    return json.dumps(
        {"protected": protected64, "payload": payload64, "signature": b64(out)}
    )

def _send_signed_request(url, payload, nonce_url, auth, account_key, err_msg):
    """Make signed request to ACME endpoint"""
    tried = 0
    nonce = do_request(nonce_url)[2]["Replay-Nonce"]
    while True:
        data = _mk_signed_req_body(url, payload, nonce, auth, account_key)
        resp_data, resp_code, headers = do_request(
            url, data=data.encode("utf8"), err_msg=err_msg
        )
        if resp_code in [200, 201, 204]:
            return resp_data, resp_code, headers
        elif (
            resp_code == 400
            and resp_data.get("type", "") == "urn:ietf:params:acme:error:badNonce"
            and tried < 100
        ):
            nonce = headers.get("Replay-Nonce", "")
            tried += 1
            continue
        else:
            sys.stderr.write(
                "{0}:\nUrl: {1}\nData: {2}\nResponse Code: {3}\nResponse: {4}".format(
                    err_msg, url, data, resp_code, resp_data
                )
            )
            sys.exit(1)

def get_public_key(account_key):
    print("Decoding private key...")
    out = cmd(["openssl", "rsa", "-in", account_key, "-noout", "-text"], err_msg="Error reading account public key")
    pub_hex, pub_exp = re.search(r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)", out.decode("utf8"), re.MULTILINE | re.DOTALL).groups()
    pub_mod = binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex))
    pub_mod64 = b64(pub_mod)
    pub_exp = int(pub_exp)
    pub_exp = "{0:x}".format(pub_exp)
    pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
    pub_exp = binascii.unhexlify(pub_exp)
    pub_exp64 = b64(pub_exp)
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
    out = cmd(["openssl", "req", "-in", csr, "-noout", "-text"], err_msg="Error reading CSR")
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
    tos = (get_directory(ca_url)["meta"]["termsOfService"])
    print(f"By continuing you are agreeing to Issuer's Subscriber Agreement\n{tos}")
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
            chl_verification = b64(hashlib.sha256(key_authorization.encode()).digest())
            TXTRec = "_acme-challenge.{}".format(domain)
            TXTValue = chl_verification
            challenges_info.append((TXTRec, TXTValue, challenge["url"]))
    return challenges_info

def dns_verification(ca_url, auth, challenge_url, account_key):
    print("Requesting verification for {}...".format(challenge_url))
    verification_result, verification_code, verification_headers = _send_signed_request(challenge_url, {}, get_directory(ca_url)["newNonce"], auth, account_key, "Error submitting challenge")
    if verification_code != 200:
        print(f"Error submitting challenge:\nUrl: {challenge_url}\nData: {json.dumps(verification_result)}\nResponse Code: {verification_code}\nResponse: {verification_result}")
        return False
    print("Challenge verified for {}!".format(challenge_url))
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
    csr_der = cmd(["openssl", "req", "-in", csr, "-outform", "DER"], err_msg="DER Export Error")
    # Finalizing the order
    fnlz_resp, fnlz_code, fnlz_headers = _send_signed_request(order["finalize"], {"csr": b64(csr_der)}, get_directory(ca_url)["newNonce"], auth, account_key, "Error finalizing order")
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
        thumbprint = b64(hashlib.sha256(json.dumps(get_public_key(account_key), sort_keys=True, separators=(',', ':')).encode()).digest())
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
