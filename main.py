import os
import sys
import time
from genPVTCSR import gen_pvt_csr
from tools import get_domains, get_ca_server, get_kid_hmac, extract_subdomains, write_file
from acme_tools import pg_client, new_account
from getTokenCert import getTokens, verifyTokens
from gen_records import txt_recs
from dns_cf import add_txt, del_txt

def cf_non_wildcard(verification_tokens, email, exchange):
    tokens = verification_tokens
    for key, value in tokens.items():
        txt_rec = txt_recs(key, exchange)
        txt_value = value[0].strip()
        try:
            del_txt(txt_rec)
        except Exception as e:
            print(f"Error deleting TXT records or no TXT records exists: {e}")
        add_txt(txt_rec, txt_value, ssl_email=email)

def cf_wildcard(verification_tokens, email, exchange):
    tokens = verification_tokens
    for key, value in tokens.items():
        txt_rec = txt_recs(key, exchange)
        try:
            del_txt(txt_rec)
        except Exception as e:
            print(f"Error deleting TXT records or no TXT records exists: {e}")
        for txt_value in value:
            add_txt(txt_rec, txt_value, ssl_email=email)

def main(i_domains, wildcard, email, ca_server, key_type, key_size=None, key_curve=None, kid=None, hmac=None):
    domains = get_domains(i_domains)
    exchange = extract_subdomains(domains=domains)
    if wildcard:
        domains = [exchange, f'*.{exchange}']
    ca_server_url = get_ca_server(ca_server, key_type)
    pgk_client = pg_client(ca_server_url, key_type=key_type, key_size=key_size, key_curve=key_curve)
    if pgk_client is None:
        exit()
    kid, hmac = get_kid_hmac(ca_server)
    if kid == 'Error' or hmac == 'Error':
        print("Try with another provider or contact us")
        sys.exit(1)
    account = new_account(pgk_client, email, kid=kid, hmac=hmac)
    if not account:
        exit()
    private_key, csr = gen_pvt_csr(domains=domains, email=email, key_type=key_type, key_curve=key_curve, key_size=key_size)
    verification_tokens, challs, order = getTokens(pgk_client, csr, ca_server_url)
    try:
        if wildcard:
            cf_wildcard(verification_tokens, email, exchange)
        else:
            cf_non_wildcard(verification_tokens, email, exchange)
    except:
        print("Error adding TXT records")
        sys.exit(1)
    for i in range(60):
        print(f"Waiting for {60-i} seconds", end="\r")
        time.sleep(1)
    cert = verifyTokens(pgk_client, challs, order)
    for key, value in verification_tokens.items():
        txt_rec = txt_recs(key, exchange)
        try:
            del_txt(txt_rec)
            print("TXT records deleted successfully")
        except Exception as e:
            print(f"Error deleting TXT records or no TXT records exists: {e}")
    path = email.split("@")[0]
    os.makedirs(path, exist_ok=True)
    write_file(f"{path}/private.pem", private_key)
    write_file(f"{path}/domain.csr", csr)
    write_file(f"{path}/cert.pem", cert)
    return private_key, f"{path}/private.pem", cert, f"{path}/cert.pem"

if __name__ == "__main__":
    DOMAINS = 'thenayankasturi.eu.org, *.thenayankasturi.eu.org'
    ca_server = "letsencrypt_test" #letsencrypt_test, letsencrypt, buypass_test, buypass, zerossl, google_test, google, ssccom
    EMAIL = "raannakasturi@mail.com"
    key_type = "ec"
    key_curve = "ec256"
    key_size = None
    KID = None
    HMAC = None
    main(i_domains=DOMAINS, wildcard=True, email=EMAIL, ca_server=ca_server, key_type=key_type, key_size=key_size,key_curve=key_curve, kid=KID, hmac=HMAC)
