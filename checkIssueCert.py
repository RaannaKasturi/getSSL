import datetime
import time
from acme import challenges
import tools

def savefile(filename, data):
    with open(filename, 'wb') as f:
        f.write(data)
    return filename

def checkDNS(verification_tokens, timeout: int = 300, interval: int = 2, authoritative: bool = False, round_robin: bool = True, verbose: bool = True):
    verified = []
    resolvers = []
    timeout = datetime.datetime.now() + datetime.timedelta(seconds=timeout)
    for domain, tokens in verification_tokens.items():
        # Create a resolver for each token required for verification of this domain.
        for token in tokens:
            resolv = tools.DNSQuery(
                domain,
                rtype='TXT',
                authoritative=authoritative,
                nameservers=["1.1.1.1", "8.8.8.8"],
                round_robin=round_robin
            )
            resolvers.append((domain, token, resolv))
    while datetime.datetime.now() < timeout:
        # Loop through each domain being verified
        for domain, token, resolver in resolvers:
            # Only try to verify the domain if it has not already been verified
            if token not in verified:
                resolver.resolve()
                # Save this domain as verified if our token was found in the TXT record values
                if token in resolver.values:
                    verified.append(token)
                # If verbose mode is enabled, print the results to the console
                if verbose:
                    action = ('found' if token in verified else 'not found')
                    values = resolver.values
                    nameserver = resolver.last_nameserver
                    msg = f"Token '{token}' for '{domain}' {action} in {values} via {nameserver}"
                    print(msg)
        # Check that all resolvers completed verification
        if len(verified) == len(resolvers):
            return True
        # Avoid flooding the DNS server(s) by briefly pausing between DNS checks
        time.sleep(interval)
    return True


def request_certificate(acme_client, responses, csr, email, wait: int = 0, timeout: int = 90):
    answers = []
    # Allow the user to specify an amount of time to wait before requesting the certificate
    time.sleep(wait)
    deadline = datetime.datetime.now() + datetime.timedelta(seconds=timeout)
    # For each domain being challenged, request answers for their challenges
    for _, challenge_list in challenges.items():
        # Request an answer for each of this domain's challenges
        for challenge in challenge_list:
            answers.append(
                acme_client.answer_challenge(challenge, responses) #if doesn't work, try responses[challenge.chall.token]
            )
        # Request our final order and save the certificate if successful
    with open(csr, 'r') as f:
        csr_pem = f.read()
    order = acme_client.new_order(csr_pem)
    final_order = acme_client.poll_and_finalize(order, deadline=deadline)
    certificate = final_order.fullchain_pem.encode()
    certFile = f"{(email.split("@")[0])}/private.pem"
    savefile(certFile, certificate)
    return certFile, certificate

def checkIssueCert(verification_tokens, acme_client, responses, domainCSR, email):
    status: bool = checkDNS(verification_tokens, timeout = 300, interval = 10, authoritative = False, round_robin = True, verbose = True)
    certFile, certificate = request_certificate(acme_client, responses, domainCSR, email, wait = 0, timeout = 90)
    return status, certFile, certificate

