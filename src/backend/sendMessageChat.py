from database.Database import Database
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
import logging
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from getPrivateKey import getPrivateKey
from getPublicKey import getPublicKey
from datetime import datetime


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
        
        # Clave publica en el backend, que se encuentra en cripto_certs/BACKEND/BACKENDcert.pem
        public_key = getPublicKey().getPublicKeyFromCertificate("cripto_certs/BACKEND/BACKENDcert.pem")
        public_key = RSA.import_key(public_key)

        # Codifica la key
        cipher_rsa = PKCS1_OAEP.new(public_key)
        key_encrypted = cipher_rsa.encrypt(key)
        logger.info(f"Se ha cifrado la key obteniendo:{key_encrypted}")


        # Firmar el HMAC con la clave privada

        # Pillar clave privada emisor
        if self.id_emisor == 13:
            username = "Ivan"
        else:
            username = "Ismael"

        private_key = getPrivateKey().getPrivateKeyFromFile("cripto_certs/"+username+"/"+username+"key.pem", self.password)
        logger.info(f"Se ha obtenido la clave privada del emisor")

        private_key = RSA.import_key(private_key)

        private_key_d = private_key.d
        private_key_n = private_key.n

        # Firmar el HMAC
        signature = pow(int(hmac_computed, 16), private_key_d, private_key_n)
        logger.info(f"Se ha firmado el HMAC obteniendo:{signature}")

        # Aquí se enviarían los certificados

        #-------------------------------------------------------------------------------

        # Verificar certificados
        def load_certificate(filepath):
            with open(filepath, "rb") as cert_file:
                cert_data = cert_file.read()
            return x509.load_pem_x509_certificate(cert_data)
        
        def verify_signature(cert, issuer_cert):
            try:
                issuer_public_key = issuer_cert.public_key()
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
                logger.info(f"Certificado {cert.subject.rfc4514_string()} es válido y está firmado por {issuer_cert.subject.rfc4514_string()}")
                return True
            except Exception as e:
                logger.error(f"Error verificando la firma entre {cert.subject.rfc4514_string()} y {issuer_cert.subject.rfc4514_string()}: {e}")
                return False
            
        def verify_validity_dates(cert):
            now = datetime.utcnow()
            if cert.not_valid_before <= now <= cert.not_valid_after:
                logger.info(f"Certificado {cert.subject.rfc4514_string()} está dentro del período de validez.")
                return True
            else:
                logger.error(f"Certificado {cert.subject.rfc4514_string()} está fuera del período de validez.")
                return False
            
        def verify_certificate_chain(cert_paths):
            # Cargar todos los certificados en el array
            certs = [load_certificate(path) for path in cert_paths]

            # Verificar cada certificado en la cadena
            for i in range(len(certs) - 1):
                cert = certs[i]
                issuer_cert = certs[i + 1]

                # Verificar fechas de validez
                if not verify_validity_dates(cert):
                    logger.error(f"Error: Certificado {cert.subject.rfc4514_string()} fuera de validez.")
                    raise Exception("Certificado "+cert.subject.rfc4514_string()+" fuera de validez.")

                # Verificar que el certificado está firmado por el emisor (issuer)
                if not verify_signature(cert, issuer_cert):
                    logger.error(f"Error: Certificado {cert.subject.rfc4514_string()} no está firmado por {issuer_cert.subject.rfc4514_string()}")
                    raise Exception("Certificado "+cert.subject.rfc4514_string()+" no está firmado por "+issuer_cert.subject.rfc4514_string())

            # Verificar fechas de validez del certificado raíz
            if not verify_validity_dates(certs[-1]):
                logger.error(f"Error: Certificado raíz {certs[-1].subject.rfc4514_string()} fuera de validez.")
                raise Exception("Certificado raíz fuera de validez.")
            
            # Verificar que el certificado raíz está firmado por sí mismo
            if not verify_signature(certs[-1], certs[-1]):
                logger.error(f"Error: Certificado raíz {certs[-1].subject.rfc4514_string()} no está firmado por sí mismo.")
                raise Exception("Certificado raíz no está firmado por sí mismo.")

            return True
        
        if self.id_emisor == 13:
            cadena_certificados = ["cripto_certs/Ivan/Ivancert.pem", "cripto_certs/ac2/ac2cert.pem", "cripto_certs/ac1/ac1cert.pem"]
        else:
            cadena_certificados = ["cripto_certs/Ismael/Ismaelcert.pem", "cripto_certs/ac2/ac2cert.pem", "cripto_certs/ac1/ac1cert.pem"]
        
        if not verify_certificate_chain(cadena_certificados):
            logger.error("Error: La cadena de certificados no es válida.")
            raise Exception("Cadena de certificados no válida.")
        
        logger.info("La cadena de certificados es válida.")

        # Descifrar la firma con la clave publica
        # Pillar clave publica emisor
        public_key = getPublicKey().getPublicKeyFromCertificate("cripto_certs/"+username+"/"+username+"cert.pem")
        logger.info(f"Se ha obtenido la clave publica del emisor")

        public_key = RSA.import_key(public_key)

        public_key_e = public_key.e
        public_key_n = public_key.n

        # Descifrar la firma
        if pow(signature, public_key_e, public_key_n) != int(hmac_computed, 16):
            logger.error(f"Las firmas no coinciden")
            raise Exception("Las firmas no coinciden")

        logger.info(f"Se ha confirmado que las firmas coinciden")
        # Clave privada en el backend, que se encuentra en cripto_certs/BACKEND/BACKENDkey.pem
        private_key = getPrivateKey().getPrivateKeyFromFile("cripto_certs/BACKEND/BACKENDkey.pem", "1234")
        private_key = RSA.import_key(private_key)

        # Decodifica la key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        key_decrypted = cipher_rsa.decrypt(key_encrypted)
        logger.info(f"Se ha decodificado la clave obteniendo:{key_decrypted}")

         # Computa el HMAC del mensaje con la key decodificada
        hmac_computed_decoded = HMAC.new(key_decrypted, digestmod=SHA256)
        hmac_computed_decoded.update(mensaje.encode())
        hmac_computed_decoded = hmac_computed_decoded.hexdigest()
        
        if hmac_computed != hmac_computed_decoded:
            logger.error(f"HMACs no coinciden, HMAC recibido: {hmac_computed}, HMAC computado: {hmac_computed_decoded}")
            raise Exception("HMACs no coinciden")
        
        logger.info(f"Se ha confirmado que el HMAC es el correcto")
        #Ahora se puede descifrar self.mensaje con la key decodificada, ya que self.message fue cifrado con la key con AES
        nonce = bytes.fromhex(ct[:16])
        ct = bytes.fromhex(ct[16:])
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        mensaje = cipher.decrypt(ct).decode()

        logger.info(f"Se ha descifrado el mensaje obteniendo:{mensaje}")

        if self.id_emisor == 13:
            public_key_emisor = getPublicKey().getPublicKeyFromCertificate("cripto_certs/Ivan/Ivancert.pem")
            public_key_receptor = getPublicKey().getPublicKeyFromCertificate("cripto_certs/Ismael/Ismaelcert.pem")
        else:
            public_key_emisor = getPublicKey().getPublicKeyFromCertificate("cripto_certs/Ismael/Ismaelcert.pem")
            public_key_receptor = getPublicKey().getPublicKeyFromCertificate("cripto_certs/Ivan/Ivancert.pem")

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

        


        
    
    