with open('certificate.pem', 'r') as file:
    data = file.read()

certs = data.split('-----BEGIN CERTIFICATE-----\n')[1:]

for i, cert in enumerate(certs, 1):
    # Preparing certificate content with BEGIN/END headers
    cert_content = f"-----BEGIN CERTIFICATE-----\n{cert.strip()}"

    # Writing to file
    file_name = f"certificate_{i}.pem"
    with open(file_name, 'w') as f:
        f.write(cert_content)
        f.write('\n')

    print(f"Certificate {i} has been written to {file_name}")
