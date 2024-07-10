import hashlib
import time

from verifyDNS import VerifyDNS
from genPrivCSR import genPrivCSR
from dnsCF import addTXT, delTXT
from signCSR import getTXT, verifyTXT

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

def prefix(domain):
    domain_bytes = domain.encode()
    prefix = hashlib.blake2b(domain_bytes, digest_size=12).hexdigest()
    return prefix

def extractSubDomains(domains):
    smallest_string = min(domains, key=len)
    result = [domain.replace(smallest_string, '').replace('.', '') for domain in domains]
    return result, smallest_string

def genCNAMERecs(domains):
    CNAMERecs = []
    for domain in domains:
        CNAMERec = f"_acme-challenge.{domain}"
        CNAMERecs.append(CNAMERec)
    return CNAMERecs

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

def checkCert(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
            if content:
                return "File not empty"
            else:
                return "File empty"
    except:
        return "File not found"

if __name__ == '__main__':
    email = "raannakasturi@gmail.com"
    iDomains = "thenayankasturi.eu.org, www.thenayankasturi.eu.org, dash.thenayankasturi.eu.org"
    cfDomain = "silerudaagartha.eu.org"
    domains = getDomains(iDomains)
    challengeType = "dns"
    privFile, csrFile, tempPrivateFile = genPrivCSR(email, domains)
    caServer = chooseCAserver("letsencrypt_test")
    cnameRecords = genCNAMERecs(domains)
    cnameValues = genCNAMEValues(domains, cfDomain)
    txtRecords = genTXTRecs(cnameValues, cfDomain)
    txtValues = cnameValues
    for i in range(len(cnameRecords)):
        print(f"Add {cnameRecords[i]} with value {cnameValues[i]} to your DNS records\n")
    addToCF(txtRecords, txtValues, email)
    loopend = True
    while loopend:
        loopend = True
        for domain in domains:
            stat, domain_status = VerifyDNS(domain)
            print(stat)
        #time.sleep(10)
        loopend = input("Do you want to continue? (y/n): ")
        if loopend == "y":
            loopend = True
            continue
        else:
            loopend = False
            break
    delFromCF(txtRecords)
    challenges_info, auth, order, order_headers, acmeTXTRecs, acmeTXTValues = getTXT(tempPrivateFile, csrFile, challengeType, caServer, email)
    addToCF(txtRecords, acmeTXTValues, email)
    time.sleep(20) #change to 60 later
    while True:
        certFile, caFile = verifyTXT(tempPrivateFile, csrFile, challenges_info, auth, order, order_headers, caServer, email)
        if checkCert(certFile) == "File not empty":
            break
        else:
            time.sleep(20)
            continue
    delFromCF(txtRecords)
    print(f"Private Key: {privFile}\nSSL Certificate: {certFile}\nCA Certificate: {caFile}")