from database.Database import Database
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
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



class sendMessageChat:
    def __init__(self, id_chat, id_emisor, id_receptor, mensaje, key, hmac):
        self.id_chat = id_chat
        self.id_emisor = id_emisor
        self.id_receptor = id_receptor
        self.mensaje = mensaje
        self.key = key
        self.hmac = hmac
        self.fecha = time.time()
        self.db = Database()
    
    def store(self):
        # Decodifica la key con la clave privada en el backend, que se encuentra en claveRSA/private_key.pem
        open_key = open("clavesRSA/private_key.pem", "rb")
        private_key = open_key.read()
        open_key.close()

        # Ahora con la clave privada, se puede decodificar la key
        key = RSA.import_key(private_key)

        # Decodifica la key
        cipher_rsa = PKCS1_OAEP.new(key)
        key = cipher_rsa.decrypt(self.key)

        # Verifica el HMAC
        h = SHA256.new()
        h.update(self.mensaje.encode())
        h = h.hexdigest()
        if h != self.hmac:
            logger.error(f"HMAC no coincide.")
            return False
        
        # Obtener claves publicas de receptor y emisor
        query = "SELECT public_key FROM Users WHERE id_user = %s OR id_user = %s"
        result = self.db.query(query, (self.id_emisor, self.id_receptor))
        # Asignar claves publicas a las variables correspondientes
        for row in result:
            if row[0] == self.id_emisor:
                public_key_emisor = row[1]
            else:
                public_key_receptor = row[1]

        # Cifrar mensaje con clave publica del receptor
        key = RSA.import_key(public_key_receptor)
        cipher_rsa = PKCS1_OAEP.new(key)
        mensaje_receptor = cipher_rsa.encrypt(self.mensaje.encode())

        # Cifrar clave con clave publica del emisor
        key = RSA.import_key(public_key_emisor)
        cipher_rsa = PKCS1_OAEP.new(key)
        mensaje_emisor = cipher_rsa.encrypt(self.mensaje.encode())

        # Insertar mensaje en la base de datos
        query = "INSERT INTO Messages (id_chat, id_emisor, id_receptor, mensaje_encriptado_emisor, mensaje_encriptado_receptor, fecha) VALUES (%s, %s, %s, %s, %s, %s)"
        self.db.query(query, (self.id_chat, self.id_emisor, self.id_receptor, mensaje_emisor, mensaje_receptor, self.fecha))

        return True

        


        
    
    