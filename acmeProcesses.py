import josepy as jose
from acme import client
from acme import messages, errors
from acme import challenges
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def load_private_key(privFile):
    with open(privFile, 'rb') as f:
        key_data = f.read()
        return serialization.load_pem_private_key(key_data, password=None, backend=default_backend())

def new_account(privFile, CAserver, email):
    with open(privFile, 'rb') as f:
        data = f.read()
    key_data = serialization.load_pem_private_key(data, password=None, backend=default_backend())
    account_key = jose.JWKRSA(key=key_data)
    net = client.ClientNetwork(account_key, user_agent='simple_acme_dns/v2')
    directory_obj = messages.Directory.from_json(net.get(CAserver).json())
    acme_client = client.ClientV2(directory_obj, net=net)
    registration = messages.NewRegistration.from_data(email=email, terms_of_service_agreed=True)
    try:
        account = acme_client.new_account(registration)
    except errors.ConflictError as e:
        print("Account already exists. Updating account email...")
        account_url = e.location
        account = acme_client.query_registration(messages.RegistrationResource(uri=account_url))
        new_registration = messages.Registration.from_data(email=email, terms_of_service_agreed=True)
        account = acme_client.update_registration(account, new_registration)
    return account_key, acme_client

def requestVerificationTokens(acme_client, csr_file, domains):
    verification_tokens = {}
    responses = {}
    with open(csr_file, 'r') as f:
        csr_pem = f.read()
    order = acme_client.new_order(csr_pem)
    for domain in domains:
        domain = f"_acme-challenge.{domain}"
        verification_tokens[domain] = []
        for authz in order.authorizations:
            for challenge in authz.body.challenges:
                if isinstance(challenge.chall, challenges.DNS01):
                    response, validation = challenge.response_and_validation(acme_client.net.key)
                    verification_tokens[domain].append(validation)
                    responses[challenge.chall.token] = response
    return verification_tokens, responses[challenge.chall.token]

def acmeProcesses(privFile, CAserver, email, csr_file, domains):
    account_key, acme_client = new_account(privFile, CAserver, email)
    acme_client_v2 = client.ClientV2(messages.Directory.from_json(client.ClientNetwork(account_key).get(CAserver).json()), net=acme_client.net)
    if not domains:
        raise ValueError("No domains specified")
    verification_tokens, responses = requestVerificationTokens(acme_client_v2, csr_file, domains)
    keyset = []
    valueset = []
    for keys, values in verification_tokens.items():
        for value in values:
            keyset.append(keys)
            valueset.append(value)
    return verification_tokens, keyset, valueset, acme_client, responses

if __name__ == '__main__':
    privFile = "raannakasturi/private.pem"
    csr_file = "raannakasturi/domain.csr"
    CAserver = "https://acme-staging-v02.api.letsencrypt.org/directory"
    email = "raannakasturi@gmail.com"
    domains = ["arktech.pp.ua", "www.arktech.pp.ua"]
    keys, values = acmeProcesses(privFile, CAserver, email, csr_file, domains)
    print(keys)
    print(values)