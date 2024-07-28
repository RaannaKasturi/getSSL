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

def getTokens(client, csr, directory):
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

def verifyTokens(client, challs, order):
    deadline = datetime.datetime.now() + datetime.timedelta(seconds=90)
    answers = []
    responses = {}
    for domain, challenge_list in challs.items():
        print(f"Processing challenges for domain: {domain}")
        for challenge in challenge_list:
            print(f"Challenge type: {challenge.chall.typ}")
            try:
                response, validation = challenge.response_and_validation(client.net.key)
            except Exception as e:
                print(f"Error generating response for challenge: {e}")
                continue
            print(f"Response: {response}")
            # Ensure responses is properly populated
            token = challenge.chall.token
            print(f"Raw token bytes: {token}, Type: {type(token)}")
            # Check if token is in bytes and decode safely
            if isinstance(token, bytes):
                try:
                    token = token.decode('utf-8', errors='replace')  # Use 'replace' to handle invalid bytes
                except Exception as e:
                    print(f"Error decoding token: {e}")
                    continue
            responses[token] = response
            try:
                answer = client.answer_challenge(challenge, response)
            except Exception as e:
                print(f"Error answering challenge: {e}")
                continue
            answers.append(answer)
            print(f"Challenge answered: {answer}")
    try:
        final_order = client.poll_and_finalize(order, deadline=deadline)
    except Exception as e:
        print(f"Error finalizing order: {e}")
        return None
    try:
        certificate = final_order.fullchain_pem.encode()
    except Exception as e:
        print(f"Error retrieving certificate: {e}")
        return None
    return certificate