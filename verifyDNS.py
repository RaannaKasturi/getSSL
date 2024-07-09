import dns.resolver

# Define a resolver instance globally to reuse for all queries
resolver = dns.resolver.Resolver()

def VerifyDNS(domain_file):
    try:
        # Read the list of domains from the file
        with open(domain_file, 'r') as f:
            domains = f.read().splitlines()
    except FileNotFoundError:
        print(f"The file '{domain_file}' was not found.")
        return
    except IOError as e:
        print(f"An error occurred while trying to read the file: {e}")
        return

    for domain in domains:
        try:
            # Query for the TXT record
            txt_answers = resolver.resolve(f"_acme-challenge.{domain}", 'TXT')
            for answer in txt_answers:
                txt_record = answer.to_text()
                if txt_record.startswith('desiredvalue@'):
                    # Redirect the TXT record
                    redirect_domain = txt_record.split('@')[1]
                    print(f"Redirecting TXT record for _acme-challenge.{domain} to {redirect_domain}")
                else:
                    print(f"TXT record for _acme-challenge.{domain} is {txt_record}")
        except dns.resolver.NXDOMAIN:
            print(f"TXT record missing for _acme-challenge.{domain}")
        except dns.resolver.NoAnswer:
            print(f"TXT record missing for _acme-challenge.{domain}")
        except dns.resolver.NoNameservers:
            print(f"TXT record missing for _acme-challenge.{domain}")

if __name__ == "__main__":
    VerifyDNS('acme_list.txt')