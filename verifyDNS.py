import dns
from dns import resolver
import dns.resolver

# Define a resolver instance globally to reuse for all queries
resolver = resolver.Resolver()

def VerifyDNS(domain):
    try:
        # Query for the TXT record
        txt_answers = resolver.resolve(f"_acme-challenge.{domain}", 'TXT')
        for answer in txt_answers:
            txt_record = answer.to_text()
            if txt_record.startswith('_acme-challenge'):
                # Redirect the TXT record
                redirect_domain = txt_record.split('@')[1]
                return f"Redirecting TXT record for _acme-challenge.{domain} to {redirect_domain}", False
            else:
                return f"TXT record for _acme-challenge.{domain} is {txt_record}", False
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.Timeout):
        return f"TXT record missing for _acme-challenge.{domain}", True
