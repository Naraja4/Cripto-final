from database.Database import Database
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
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
    def __init__(self, id_chat, id_emisor, id_receptor, mensaje, fecha):
        self.id_chat = id_chat
        self.id_emisor = id_emisor
        self.id_receptor = id_receptor
        self.mensaje = mensaje
        self.fecha = time.time()
        self.db = Database()
    
    def sendMessage(self):
        self.db.query(f"INSERT INTO Messages (id_chat, id_emisor, id_receptor, mensaje, fecha) VALUES ('{self.id_chat}', '{self.id_emisor}', '{self.id_receptor}', '{self.mensaje}', '{self.fecha}')")
        self.db.cnx.commit()
        logger.info(f"Mensaje de {self.id_emisor} a {self.id_receptor} ha sido introducido a la base de datos.")
        return True
    
    