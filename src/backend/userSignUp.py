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
        logger.info(f"AES de password es: {AES_key.hexdigest()}")

        # Crear un nonce de 8 bytes para el modo CTR
        nonce = get_random_bytes(8)

        # Encrypt private key with AES with key derived from password
        cipher = AES.new(AES_key.digest(), AES.MODE_CTR, nonce=nonce)

        private_key = key.export_key()
        encrypted_key = cipher.encrypt(private_key)
        encrypted_key = nonce + encrypted_key
        
        logger.info(f"Clave privada ha sido encriptada con AES.")

        public_key = key.publickey().export_key()

        logger.info(f"Clave privada es: {private_key}")
        logger.info(f"Clave privada encriptada es: {encrypted_key.hex()}")
        
        query = """
            INSERT INTO Users (username, salt, hashed_password, public_key, encrypted_private_key) 
            VALUES (%s, %s, %s, %s, %s)
        """
        values = (self.username, salt, hashed_password, public_key, encrypted_key.hex())

        self.db.query(query, values)
        self.db.cnx.commit()
        logger.info(f"{self.username} {self.password} ha sido introducido a la base de datos.")

    def __hash_password(self, password: str, salt: str) -> str:
        password_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        sha256 = SHA256.new()
        sha256.update(salt_bytes + password_bytes)
        hashed_password = sha256.hexdigest()

        return hashed_password
    
    