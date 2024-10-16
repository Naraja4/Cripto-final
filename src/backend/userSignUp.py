from database.Database import Database
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler('logger.log', mode='w')
file_handler.setLevel(logging.INFO)
file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
file_handler.setFormatter(file_formatter)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
console_handler.setFormatter(console_formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)



class UserSignUp:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.db = Database()
    
    def signup(self):
        key = RSA.generate(2048)
        salt = get_random_bytes(32).hex()
        hashed_password = self.__hash_password(self.password, salt)
        logger.info(f"Contraseña {self.password} ha sido hasheada con SHA256.")

        #SHA-256 hash of the password to use as the AES key
        AES_key = SHA256.new()
        AES_key.update(self.password.encode())

        # Encrypt private key with AES with key derived from password
        cipher = AES.new(AES_key.digest(), AES.MODE_EAX)

        # Take out -----BEGIN PRIVATE----- and -----END PRIVATE KEY-----
        private_key = key.export_key()
        private_key = private_key.split(b'\n')[1:-1]
        private_key = b''.join(private_key)

        encrypted_key, tag = cipher.encrypt_and_digest(private_key)
        logger.info(f"Clave privada ha sido encriptada con AES.")

        #Take out -----BEGIN PUBLIC KEY----- and -----END PUBLIC KEY-----
        public_key = key.publickey().export_key()
        public_key = public_key.split(b'\n')[1:-1]
        public_key = b''.join(public_key)
        
        self.db.query(f"INSERT INTO Users (username, salt, hashed_password, public_key, encrypted_private_key) VALUES ('{self.username}', '{salt}', '{hashed_password}', '{public_key.hex()}', '{encrypted_key.hex()}')")
        self.db.cnx.commit()
        
        logger.info(f"{self.username} {self.password} ha sido introducido a la base de datos.")

    def __hash_password(self, password: str, salt: str) -> str:
        password_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        sha256 = SHA256.new()
        sha256.update(salt_bytes + password_bytes)
        hashed_password = sha256.hexdigest()

        return hashed_password
    
    