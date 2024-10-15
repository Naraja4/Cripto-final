from database import Database
from Crypto.Hash import SHA256
import logging

# Configurar el logger
logging.basicConfig(level=logging.DEBUG,  # Nivel de log
                    format='%(asctime)s - %(levelname)s - %(message)s',  # Formato del mensaje
                    datefmt='%Y-%m-%d %H:%M:%S')

# Crear una instancia del logger
logger = logging.getLogger(__name__)

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

            salt = data[0][2]
            hash = data[0][3]

            # Validar la contraseña
            if self.__hash_password(self.password, salt) == hash:
                logger.info(f"Inicio de sesión exitoso para el usuario: {self.username}")
                return True
            else:
                logger.warning(f"Inicio de sesión fallido para el usuario: {self.username}. Contraseña incorrecta.")
        else:
            logger.warning(f"Usuario '{self.username}' no encontrado en la base de datos.")
        
        return False
    
    def lookupUsername(self):
        try:
            query = f"SELECT * FROM users WHERE username = '{self.username}'"
            logger.debug(f"Ejecutando consulta SQL: {query}")
            result = self.db.query(query)
            return result
        except Exception as e:
            logger.error(f"Error al consultar la base de datos: {e}")
            return None

    def __hash_password(self, password: str, salt: str) -> str:
        password_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        sha256 = SHA256.new()
        sha256.update(salt_bytes + password_bytes)
        hashed_password = sha256.hexdigest()
        
        logger.debug(f"Contraseña hash generada para el usuario: {self.username}")
        
        return hashed_password
