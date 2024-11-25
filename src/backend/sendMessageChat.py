from database.Database import Database
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
import logging
import time
from getPrivateKey import getPrivateKey
from getPublicKey import getPublicKey


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



class sendMessageChat:
    def __init__(self, id_chat, id_emisor, id_receptor, mensaje, password):
        self.id_chat = id_chat
        self.id_emisor = id_emisor
        self.id_receptor = id_receptor
        self.mensaje = mensaje
        self.password = password
        self.db = Database()
    
    def store(self):
        # Genera clave para AES/HMAC
        mensaje = self.mensaje
        key = get_random_bytes(32)
        logger.info(f"Se ha generado la clave :{key}")
        
        # Cifrar mensaje con AES
        nonce = get_random_bytes(8)
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        ct_bytes = cipher.encrypt(mensaje.encode())
        ct = nonce + ct_bytes
        ct = ct.hex()

        logger.info(f"Se ha codificado el mensaje obteniendo:{ct}")

        # Con la key, haz HMAC del mensaje usando key como clave
        hmac_computed = HMAC.new(key, digestmod=SHA256)
        hmac_computed.update(mensaje.encode())
        hmac_computed = hmac_computed.hexdigest()

        logger.info(f"Se ha generado la clave HMAC que es :{hmac_computed}")
        
        # Clave publica en el backend, que se encuentra en claveRSA/public_key.pem
        open_key = open("clavesRSA/public_key.pem", "rb")
        public_key = open_key.read()
        open_key.close()
        public_key = RSA.import_key(public_key)

        # Codifica la key
        cipher_rsa = PKCS1_OAEP.new(public_key)
        key_encrypted = cipher_rsa.encrypt(key)
        logger.info(f"Se ha cifrado la key obteniendo:{key_encrypted}")


        # Firmar el HMAC con la clave privada

        # Pillar clave privada emisor
        private_key = getPrivateKey().getPrivateKey_withId(self.id_emisor, self.password)
        logger.info(f"Se ha obtenido la clave privada del emisor")

        private_key = RSA.import_key(private_key)

        private_key_d = private_key.d
        private_key_n = private_key.n

        # Firmar el HMAC
        signature = pow(int(hmac_computed, 16), private_key_d, private_key_n)
        logger.info(f"Se ha firmado el HMAC obteniendo:{signature}")

        #-------------------------------------------------------------------------------

        # Descifrar la firma con la clave publica
        # Pillar clave publica emisor
        public_key = getPublicKey().getPublicKey_withId(self.id_emisor)
        logger.info(f"Se ha obtenido la clave publica del emisor")

        public_key = RSA.import_key(public_key)

        public_key_e = public_key.e
        public_key_n = public_key.n

        # Descifrar la firma
        if pow(signature, public_key_e, public_key_n) != int(hmac_computed, 16):
            logger.error(f"Las firmas no coinciden")
            return False

        logger.info(f"Se ha confirmado que las firmas coinciden")
        # Clave privada en el backend, que se encuentra en claveRSA/private_key.pem
        open_key = open("clavesRSA/private_key.pem", "rb")
        private_key = open_key.read()
        open_key.close()
        private_key = RSA.import_key(private_key)

        # Decodifica la key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        key_decrypted = cipher_rsa.decrypt(key_encrypted)
        logger.info(f"Se ha decodificado la clave obteniendo:{key_decrypted}")
        print("Decoded key: ", key_decrypted)

         # Computa el HMAC del mensaje con la key decodificada
        hmac_computed_decoded = HMAC.new(key_decrypted, digestmod=SHA256)
        hmac_computed_decoded.update(mensaje.encode())
        hmac_computed_decoded = hmac_computed_decoded.hexdigest()
        
        if hmac_computed != hmac_computed_decoded:
            print("HMAC computed: ", hmac_computed)
            print("HMAC computed decoded: ", hmac_computed_decoded)
            print("HMACs do not match")
            return False
        logger.info(f"Se ha confirmado que el HMAC es el correcto")
        #Ahora se puede descifrar self.mensaje con la key decodificada, ya que self.message fue cifrado con la key con AES
        nonce = bytes.fromhex(ct[:16])
        ct = bytes.fromhex(ct[16:])
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        mensaje = cipher.decrypt(ct).decode()

        logger.info(f"Se ha descifrado el mensaje obteniendo:{mensaje}")
        
        # Obtener claves publicas de receptor y emisor
        query = "SELECT id_usuario, public_key FROM Users WHERE id_usuario = %s OR id_usuario = %s"
        result = self.db.query(query, (self.id_emisor, self.id_receptor))
        print(result)
        # Asignar claves publicas a las variables correspondientes
        for row in result:
            if row[0] == self.id_emisor:
                public_key_emisor = row[1]
            else:
                public_key_receptor = row[1]
        logger.info(f"La clave publica del receptor es:{public_key_emisor}")
        # Cifrar mensaje con clave publica del receptor
        key = RSA.import_key(public_key_receptor)
        logger.info(f"La clave publica del receptor es:{public_key_receptor}")
        cipher_rsa = PKCS1_OAEP.new(key)
        mensaje_receptor = cipher_rsa.encrypt(mensaje.encode()).hex()
        # Cifrar clave con clave publica del emisor
        key = RSA.import_key(public_key_emisor)
        cipher_rsa = PKCS1_OAEP.new(key)
        mensaje_emisor = cipher_rsa.encrypt(mensaje.encode()).hex()
        logger.info(f"Se ha cifrado el mensaje con la clave publica del emisor y se ha alamcenado en la base de datos")
        # Insertar mensaje en la base de datos
        query = "INSERT INTO Mensajes (id_chat, id_emisor, id_receptor, mensaje_encriptado_emisor, mensaje_encriptado_receptor) VALUES (%s, %s, %s, %s, %s)"
        self.db.query(query, (self.id_chat, self.id_emisor, self.id_receptor, mensaje_emisor, mensaje_receptor))
        self.db.cnx.commit()

        return True

        


        
    
    