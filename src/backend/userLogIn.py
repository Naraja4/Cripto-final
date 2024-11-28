from database.Database import Database
from Crypto.Hash import SHA256
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

class UserLogIn:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.db = Database()
    
    def login(self):
        logger.info(f"Intento de inicio de sesión para el usuario: {self.username}")

        data = self.lookupUsername()

        if data:
            logger.debug(f"Usuario '{self.username}' encontrado en la base de datos.")

            hash = data[0][2]
            salt = data[0][3]

            logger.debug(f"Salt y hash recuperados de la base de datos para el usuario: {self.username}")

            # Validar la contraseña
            if self.__hash_password(self.password, salt) == hash:
                logger.info(f"Inicio de sesión exitoso para el usuario: {self.username}")
                return True
            else:
                logger.warning(f"Inicio de sesión fallido para el usuario: {self.username}. Contraseña incorrecta.")
        else:
            logger.warning(f"Usuario '{self.username}' no encontrado en la base de datos.")
        
        raise Exception("Inicio de sesión fallido. Usuario o contraseña incorrectos.")
    
    def lookupUsername(self):
        try:
            query = "SELECT * FROM Users WHERE username = %s"
            logger.debug(f"Ejecutando consulta SQL: {query}")
            result = self.db.query(query, (self.username,))
            return result
        except Exception as e:
            logger.error(f"Error al consultar la base de datos: {e}")
            raise Exception("Error al consultar la base de datos.")


    def __hash_password(self, password: str, salt: str) -> str:
        password_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        sha256 = SHA256.new()
        sha256.update(salt_bytes + password_bytes)
        hashed_password = sha256.hexdigest()
        
        logger.debug(f"Hash de salt + contraseña generada para el usuario: {self.username}")
        
        return hashed_password
