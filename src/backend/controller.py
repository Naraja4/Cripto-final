from typing import Union
from fastapi import FastAPI, HTTPException
from userLogIn import UserLogIn
from userSignUp import UserSignUp
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from getPublicKey import getPublicKey
from getPrivateKey import getPrivateKey
from sendMessageChat import sendMessageChat
from getMessagesChat import getMessagesChat
import logging


#Configurar logger
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

app = FastAPI()

origins = [
    "http://127.0.0.1:8000",  # Servidor de desarrollo frontend
]

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,            # Permitir origins
    allow_credentials=True,           # Permitir cookies y authentication
    allow_methods=["*"],              # Permitir todos los métodos HTTP (GET, POST, etc.)
    allow_headers=["*"],              # Permitir todos los encabezados
)

class LoginRequest(BaseModel):
    username: str
    password: str

class Message(BaseModel):
    id_chat: int
    id_emisor: int
    id_receptor: int
    mensaje: str
    password: str

@app.post("/api/v1/login")
async def login_view(login_request: LoginRequest):
    try:
        UserLogIn(login_request.username, login_request.password).login()
        logger.info("Se ha iniciado sesión")
        return {"login": "success"}, 200
    except Exception as e:
        logger.error("No se ha podido iniciar sesión debido a: " + str(e))
        return {"login": "failed"}, 401

@app.post("/api/v1/signup")
async def signup_view(login_request: LoginRequest):
    try: 
        UserSignUp(login_request.username, login_request.password).signup()
        logger.info("Se ha registrado el usuario")
        return {"signup": "success"}, 200
    except Exception as e:
        logger.error("No ha podido registrarse el usuario debido a: " + str(e))
        return {"signup": "failed"}, 400

@app.post("/api/v1/send-message")
async def send_message_view(message: Message):
    try:
        sendMessageChat(message.id_chat, message.id_emisor, message.id_receptor, message.mensaje, message.password).store()
        return {"message": "success"}, 200
    except Exception as e:
        logger.error("No se ha podido enviar el mensaje debido a: " + str(e))
        return {"message": "failed"}, 400

@app.get("/api/v1/get-messages/{id_chat}/{username}/{password}")
async def get_messages_view(id_chat: int, username: str, password: str):
    try:
        messages = getMessagesChat(id_chat, username, password).getMessages()
        return {"messages": messages}
    except Exception as e:
        logger.error("No se ha podido obtener los mensajes debido a: " + str(e))
        return {"messages": "failed"}, 400

@app.get("/api/v1/get-private-key/{username}/{password}")
async def get_private_key_view(username: str, password: str):
    try:
        key = getPrivateKey().getPrivateKey(username, password)
        key = key.decode()
        logger.info("Se ha obtenido la clave privada")
        return {"private_key": key}
    except Exception as e:
        logger.error("No se ha podido obtener la clave privada debido a: " + str(e))
        raise HTTPException(status_code=400, detail="No se ha podido obtener la clave privada")


@app.get("/api/v1/get-public-key/{username}")
async def get_public_key_view(username: str):
    try:
        key = getPublicKey().getPublicKey(username)
        logger.info("Se ha obtenido la clave pública")
        return {"public_key": key}
    except Exception as e:
        logger.error("No se ha podido obtener la clave pública debido a: " + str(e))
        raise HTTPException(status_code=400, detail="No se ha podido obtener la clave pública")
    

    # Para posible uso futuro
'''@app.get("/api/v1/get-backend-public-key")
async def get_backend_public_key():
    try:
        with open("clavesRSA/public_key.pem", "rb") as public_file:
            public_key = public_file.read()
            return {"public_key": public_key}
    except Exception as e:
        #Retrun http code 400
        raise HTTPException(status_code=400, detail="Failed to retrieve backend public key")'''

    