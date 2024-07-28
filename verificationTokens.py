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

def verificationTokens(client, csr, directory):
    verification_tokens = {}
    responses = {}
    order = client.new_order(csr)
    chall = challens(order, directory)
    for domain, challenge_items in chall.items():
        domain = f"_acme-challenge.{domain}"
        for challenge in challenge_items:
            verification_tokens[domain] = verification_tokens[domain] if domain in verification_tokens else []
            response, validation = challenge.response_and_validation(client.net.key)
            verification_tokens[domain].append(validation)
            responses[challenge.chall.token] = response
    _verification_tokens = verification_tokens
    return verification_tokens