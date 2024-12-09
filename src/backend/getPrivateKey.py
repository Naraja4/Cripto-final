from database.Database import Database
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import logging
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend



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



class getPrivateKey:
    def __init__(self):
        self.db = Database()
    
    def getPrivateKeyFromFile(self, private_key_path, password):
        # Read the encrypted private key file
        with open(private_key_path, 'rb') as key_file:
            encrypted_key = key_file.read()
        
        # Load and decrypt the private key
        private_key = serialization.load_pem_private_key(
            encrypted_key,
            password=password.encode(),  # Convert password to bytes
            backend=default_backend()
        )

        # Serialize the private key to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()  # No encryption for the output PEM
        )
        
        # Return the text representation of the private key
        return private_key_pem.decode('utf-8')

        
            

            