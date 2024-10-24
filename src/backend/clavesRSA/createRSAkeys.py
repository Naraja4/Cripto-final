from Crypto.PublicKey import RSA

def generate_rsa_keys():
    # Generate a 2048-bit RSA key pair
    key = RSA.generate(2048)

    # Extract the private key and save it to a file
    private_key = key.export_key()

    with open("private_key.pem", "wb") as private_file:
        private_file.write(private_key)

    # Extract the public key and save it to a file
    public_key = key.publickey().export_key()
    
    with open("public_key.pem", "wb") as public_file:
        public_file.write(public_key)

generate_rsa_keys()