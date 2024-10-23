from database.Database import Database
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import logging
import time


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



class getPrivateKey:
    def __init__(self):
        self.db = Database()
    
    def getPrivateKey(self, username, password):
        try:
            logger.info(f"Obteniendo clave privada de usuario {username}.")
            logger.info(f"Contraseña de usuario {username} es: {password}")
            query = "SELECT encrypted_private_key FROM Users WHERE username = %s"
            logger.debug(f"Ejecutando consulta SQL: {query}")
            result = self.db.query(query, (username,))

            encrypted_data = bytes.fromhex(result[0][0])

            #SHA-256 hash of the password to use as the AES key
            AES_key = SHA256.new()
            AES_key.update(password.encode())

            # FIX HERE, result[0][0] is not a string, it is a bytes object, but it is being treated as a string
            nonce = encrypted_data[:8]
            print(f"Nonce es: {nonce}")
            encrypted_key = encrypted_data[8:]
            print(f"Clave privada encriptada es: {encrypted_key}")

            logger.info(f"AES de password es: {AES_key.hexdigest()}")

            # Decrypt private key with AES with key derived from password
            cipher = AES.new(AES_key.digest(), AES.MODE_CTR, nonce=nonce)
            logger.info(f"result[0][0] es: {result[0][0]}")
            private_key = cipher.decrypt(encrypted_key)
            logger.info(f"Clave privada ha sido desencriptada con AES.")
            logger.info(f"Clave privada es: {private_key.decode()}")
            return private_key

        
        except Exception as e:
            logger.error(f"Error al consultar la base de datos: {e}")
            raise e
    
    