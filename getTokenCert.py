import datetime
from acme import errors, challenges

def challens(order, directory) -> dict:
    challs = {}
    for auth in list(order.authorizations):
        for challenge in auth.body.challenges:
            if isinstance(challenge.chall, challenges.DNS01):
                domain = auth.body.identifier.value
                challs[domain] = challs[domain] if domain in challs else []
                challs[domain].append(challenge)
    if not challs:
        msg = f"ACME server at '{directory}' does not support DNS-01 challenge."
        raise errors.ChallengeUnavailable(msg.format(directory=str(directory)))
    return challs

def get_tokens(client, csr, directory):
    verification_tokens = {}
    responses = {}
    order = client.new_order(csr)
    challs = challens(order, directory)
    for domain, challenge_items in challs.items():
        domain = f"_acme-challenge.{domain}"
        for challenge in challenge_items:
            verification_tokens[domain] = verification_tokens[domain] if domain in verification_tokens else []
            response, validation = challenge.response_and_validation(client.net.key)
            verification_tokens[domain].append(validation)
            responses[challenge.chall.token] = response
    _verification_tokens = verification_tokens
    return verification_tokens, challs, order

def process_challenge(client, challenge, domain):
    try:
        response, _validation = challenge.response_and_validation(client.net.key)
        print(f"Challenge verified for domain: {domain}")
        token = challenge.chall.token
        if isinstance(token, bytes):
            token = token.decode('utf-8', errors='replace')
        return response, token
    except Exception as e:
        print(f"Error processing challenge for domain {domain}: {e}")
        return None, None

def answer_challenge(client, challenge, response, domain):
    try:
        answer = client.answer_challenge(challenge, response)
        print(f"Challenge answered for domain: {domain}")
        return answer
    except Exception as e:
        print(f"Error answering challenge for domain {domain}: {e}")
        return None

def finalize_order(client, order, deadline):
    try:
        return client.poll_and_finalize(order, deadline=deadline)
    except Exception as e:
        print(f"Error finalizing order: {e}")
        return None

def retrieve_certificate(final_order):
    try:
        return final_order.fullchain_pem.encode()
    except Exception as e:
        print(f"Error retrieving certificate: {e}")
        return None
    
def verify_tokens(client, challs, order):
    deadline = datetime.datetime.now() + datetime.timedelta(seconds=90)
    answers = []
    responses = {}
    for domain, challenge_list in challs.items():
        print(f"Fetching challenges for domain: {domain}")
        for challenge in challenge_list:
            response, token = process_challenge(client, challenge, domain)
            if response is None:
                continue
            
            responses[token] = response
            answer = answer_challenge(client, challenge, response, domain)
            if answer is not None:
                answers.append(answer)
    final_order = finalize_order(client, order, deadline)
    if final_order is None:
        return None
    cert = retrieve_certificate(final_order)
    return cert