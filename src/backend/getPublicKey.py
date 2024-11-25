from database.Database import Database
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import logging
import time


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
#logger.addHandler(console_handler)



class getPublicKey:
    def __init__(self):
        self.db = Database()
    
    def getPublicKey(self, username):
        try:
            query = "SELECT public_key FROM Users WHERE username = %s"
            logger.debug(f"Ejecutando consulta SQL: {query}")
            result = self.db.query(query, (username,))
            print(f"Resultado de la consulta: {result[0][0]}")
            return result[0][0]
        except Exception as e:
            logger.error(f"Error al consultar la base de datos: {e}")
            return None
        
    def getPublicKey_withId(self, id_user):
        try:
            query = "SELECT public_key FROM Users WHERE id_usuario = %s"
            logger.debug(f"Ejecutando consulta SQL: {query}")
            result = self.db.query(query, (id_user,))
            print(f"Resultado de la consulta: {result[0][0]}")
            return result[0][0]
        except Exception as e:
            logger.error(f"Error al consultar la base de datos: {e}")
            return None
    
    