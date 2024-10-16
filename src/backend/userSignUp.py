from database.Database import Database
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
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
        salt = get_random_bytes(32).hex()
        hashed_password = self.__hash_password(self.password, salt)
        logger.info(f"Contraseña {self.password} ha sido hasheada con SHA256.")
        self.db.query(f"INSERT INTO users (username, salt, hash) VALUES ('{self.username}', '{salt}', '{hashed_password}')")
        logger.info(f"{self.username} {self.password} ha sido introducido a la base de datos.")

    def __hash_password(self, password: str, salt: str) -> str:
        password_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        sha256 = SHA256.new()
        sha256.update(salt_bytes + password_bytes)
        hashed_password = sha256.hexdigest()

        return hashed_password
    
    