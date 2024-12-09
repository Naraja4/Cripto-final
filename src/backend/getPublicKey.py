from database.Database import Database
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import logging
import time
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization



logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler('logger.log', mode='a')
file_handler.setLevel(logging.INFO)
file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
file_handler.setFormatter(file_formatter)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
console_handler.setFormatter(console_formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)



class getPublicKey:
    def __init__(self):
        self.db = Database()
    
    def getPublicKeyFromCertificate(self, certificate_path):    
        # Read the certificate file
        with open(certificate_path, 'rb') as cert_file:
            cert_data = cert_file.read()
        
        # Load the certificate
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        # Extract the public key
        public_key = cert.public_key()

        # Serialize the public key to PEM format
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Return the text representation of the public key
        return public_key_pem.decode('utf-8')
            

        