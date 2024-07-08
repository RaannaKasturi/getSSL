import datetime
import hashlib
import os
import time
from genPrivCSR import genPrivCSR
from acmeProcesses import acmeProcesses
from dnsCF import addTXT, delTXT
from checkIssueCert import checkIssueCert

def getDomains(iDomains):
    domains = []
    for domain in iDomains.split(","):
        domain = domain.strip()
        domains.append(domain)
    return domains

def chooseCAserver(provider):
    if provider == "letsencrypt":
        return "https://acme-v02.api.letsencrypt.org/directory"
    elif provider == "letsencrypt_test":
        return "https://acme-staging-v02.api.letsencrypt.org/directory"
    elif provider == "buypass":
        return "https://api.buypass.com/acme/directory"
    elif provider == "buypass_test":
        return "https://api.test4.buypass.no/acme/directory"
    elif provider == "zerossl":
        return "https://acme.zerossl.com/v2/DV90"
    elif provider == "sslcomRSA":
        return "https://acme.ssl.com/sslcom-dv-rsa"
    elif provider == "sslcomECC":
        return "https://acme.ssl.com/sslcom-dv-ecc"
    elif provider == "google":
        return "https://dv.acme-v02.api.pki.goog/directory"
    elif provider == "googletest":
        return "https://dv.acme-v02.test-api.pki.goog/directory"
    else:
        print("Invalid provider.")
        return None

def genCSR(email, domains, key_type="", common_name="", country="", state="", locality="", organization="", organization_unit=""):
    domainset = []
    for domain in domains:
        domain = domain.strip()
        if domain.startswith("*."):
            print("Wildcard domains are not supported")
            exit(1)
        else:
            domainset.append(domain)
    domainset = domains
    if key_type.lower() == '':
        key_type = 'rsa2048'
    if key_type.lower() not in ['ec256', 'ec384', 'rsa2048', 'rsa4096']:
        print(f"Invalid private key type '{key_type}'. Options: ['ec256', 'ec384', 'rsa2048', 'rsa4096']")
        exit(1)
    else:
        key_type = key_type.lower()
    if common_name == '':
        common_name = domains[0]
    if country == '':
        country = 'IN'
    if state == '':
        state = 'Maharashra'
    if locality == '':
        locality = 'Mumbai'
    if organization == '':
        organization = domains[0].split(".")[0]
    if organization_unit == '':
        organization_unit = 'IT'
    if email == '':
        print("Email is required")
        exit(1)
    elif '@' not in email:
        print("Invalid email")
        exit(1)
    elif (email.split("@")[1]) == "example.com" or (email.split("@")[1]) == "demo.com":
        print(email.split("@")[1])
        print("Please provide your original email")
        exit(1)
    else:
        email = email
    os.makedirs(f"{(email.split("@")[0])}", exist_ok=True)
    privFile = f"{(email.split("@")[0])}/private.pem"
    csrFile = f"{(email.split("@")[0])}/domain.csr"
    private_key, csr = genPrivCSR(key_type, privFile, csrFile, common_name, country, state, locality, organization, organization_unit, email, domains)
    return private_key, csr

def acmeProcess(email, domains, privFile, csrFile, CAserver):
    verification_tokens, keyset, valueset, acme_client, responses = acmeProcesses(privFile, CAserver, email, csrFile, domains)
    return verification_tokens, keyset, valueset, acme_client, responses

def prefix(domain):
    domain_bytes = domain.encode()
    prefix = hashlib.blake2b(domain_bytes, digest_size=12).hexdigest()
    return prefix

def extractSubDomains(domains):
    smallest_string = min(domains, key=len)
    result = [domain.replace(smallest_string, '').replace('.', '') for domain in domains]
    return result, smallest_string

def genCNAMEValues(domains, cfDomain):
    tempCNAMEValues = []
    CNAMEValues = []
    subdomains, exchange = extractSubDomains(domains)
    for domain in domains:
        CNAMEValue = prefix(domain)
        CNAMEValue = f"{CNAMEValue}.{domain}"
        tempCNAMEValues.append(CNAMEValue)
    for CNAMEValue in tempCNAMEValues:
        modified_CNAMEValue = CNAMEValue.replace(exchange, cfDomain)
        CNAMEValues.append(modified_CNAMEValue)
    return CNAMEValues

def genTXTRecs(CNAMEValues, cfDomain):
    TXTRecs = []
    for CNAMEValue in CNAMEValues:
        TXTRec = CNAMEValue.replace(f".{cfDomain}", "")
        TXTRecs.append(TXTRec)
    return TXTRecs

def addToCF(txtRecords, txtValues, email):
    try:
        for i in range(len(txtRecords)):
            print(f"Adding {txtRecords[i]} with value {txtValues[i]} to your DNS records")
            addTXT(txtRecords[i].strip(), txtValues[i].strip(), email)
        return "TXT records added successfully"
    except:
        return "error adding TXT records"
    
def delFromCF(txtRecords):
    try:
        for txtRecord in txtRecords:
            status = delTXT(txtRecord)
            if status:
                stmt = f"TXT records deleted successfully"
            else:
                stmt = f"TXT records not found"
    except:
        stmt = "error deleting TXT records"
    return stmt

if __name__ == '__main__':
    email = "raannakasturi@gmail.com"
    iDomains = "thenayankasturi.eu.org, www.thenayankasturi.eu.org, mail.thenayankasturi.eu.org"
    cfDomain = "silerudaagartha.eu.org"
    domains = getDomains(iDomains)
    caServer = chooseCAserver("letsencrypt_test")
    privateKey, domainCSR = genCSR(email, domains)
    verification_tokens, cnameRecords, txtValues, acme_client, responses = acmeProcess(email, domains, privateKey, domainCSR, caServer)
    cnameValues = genCNAMEValues(domains, cfDomain)
    txtRecords = genTXTRecs(cnameValues, cfDomain)  
    for i in range(len(cnameRecords)):
        print(f"Add {cnameRecords[i]} with value {cnameValues[i]} to your DNS records\n")
    #time.sleep(60) #change to 60 later
    addToCF(txtRecords, txtValues, email)
    #time.sleep(30) #change to 60 later
    status, certFile, certificate = checkIssueCert(verification_tokens, acme_client, responses, domainCSR, email)
    print(f"DNS Status: {status}")
    print(f"Certificate saved to {certFile}")
    delFromCF(txtRecords)

