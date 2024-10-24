from database.Database import Database
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import logging
import time
from getPrivateKey import getPrivateKey

'''
1- Recibe el id_chat, id_usuario y password
2- Saca la clave privada del usuario usando la funcion getPrivateKey con el id_usuario y password
3- Saca los mensajes del chat con el id_chat, separa los mensajes del emisor y receptor
4- Desencripta cada mensaje con la clave privada del usuario
5- Devuelve los mensajes desencriptados
'''


class getMessagesChat:
    def __init__(self, id_chat, id_user, password):
        self.id_chat = id_chat
        self.db = Database()
        self.id_user = self.__get_user_id(id_user)
        self.username = id_user
        self.password = password
        
    
    def getMessages(self):
        try:
            private_key = getPrivateKey().getPrivateKey(self.username, self.password).decode()
            query = "SELECT id_emisor, id_receptor, mensaje_encriptado_receptor, mensaje_encriptado_emisor FROM Mensajes WHERE id_chat = %s ORDER BY fecha ASC"
            result = self.db.query(query, (self.id_chat,))
            messages = []
            for row in result:
                emisor = row[0]
                
                print("Emisor: ", emisor)
                print("self.id_user: ", self.id_user)
                if emisor == self.id_user:
                    mensaje = row[3]
                else:
                    mensaje = row[2]

                mensaje = self.__decrypt_message(mensaje, private_key)
                
                messages.append({"contenido": mensaje, "enviado_por_ti": emisor == self.id_user})
            return messages
        except Exception as e:
            raise e
    
    def __decrypt_message(self, mensaje, private_key):
        try:
            print("Clave privada: ", private_key)
            mensaje = bytes.fromhex(mensaje)
            private_key = RSA.import_key(private_key)
            cipher_rsa = PKCS1_OAEP.new(private_key)
            mensaje = cipher_rsa.decrypt(mensaje).decode()
            return mensaje
        except Exception as e:
            raise e
        
    def __get_user_id(self, username):
        query = "SELECT id_usuario FROM Users WHERE username = %s"
        result = self.db.query(query, (username,))
        return result[0][0]
        