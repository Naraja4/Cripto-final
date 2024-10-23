from typing import Union
from fastapi import FastAPI, HTTPException
from userLogIn import UserLogIn
from userSignUp import UserSignUp
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from getPublicKey import getPublicKey
from getPrivateKey import getPrivateKey
from sendMessageChat import sendMessageChat

app = FastAPI()

origins = [
    "http://127.0.0.1:8000",  # Frontend development server
]

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,            # Allowed origins
    allow_credentials=True,           # Allow cookies and authentication
    allow_methods=["*"],              # Allow all HTTP methods (GET, POST, etc.)
    allow_headers=["*"],              # Allow all headers
)

@app.get("/api/v1/hello")
def read_root():
    return {"Hello": "World"}

class LoginRequest(BaseModel):
    username: str
    password: str

class Message(BaseModel):
    id_chat: int
    id_emisor: int
    id_receptor: int
    mensaje: str
    key: str
    hmac: str

@app.post("/api/v1/login")
async def login_view(login_request: LoginRequest):
    if UserLogIn(login_request.username, login_request.password).login():
        return {"login": "success"}, 200
    else:
        return {"login": "failed"}, 401

@app.post("/api/v1/signup")
async def signup_view(login_request: LoginRequest):
    if UserSignUp(login_request.username, login_request.password).signup():
        return {"signup": "success"}, 200
    else:
        return {"signup": "failed"}, 400

@app.post("/api/v1/send-message")
async def send_message_view(message: Message):
    if sendMessageChat(message.id_chat, message.id_emisor, message.id_receptor, message.mensaje).sendMessage():
        return {"message": "success"}, 200
    else:
        return {"message": "failed"}, 400

@app.get("/api/v1/get-messages")
async def get_messages_view():
    return {"messages": "messages"}

@app.get("/api/v1/get-private-key/{username}/{password}")
async def get_private_key_view(username: str, password: str):
    try:
        key = getPrivateKey().getPrivateKey(username, password)
        key = key.decode()
        print(key)
        return {"private_key": key}
    except:
        #Retrun http code 400
        raise HTTPException(status_code=400, detail="Failed to retrieve private key")



@app.get("/api/v1/get-public-key/{username}")
async def get_public_key_view(username: str):
    try:
        key = getPublicKey().getPublicKey(username)
        return {"public_key": key}
    except:
        #Retrun http code 400
        print("Failed to retrieve public key")
        raise HTTPException(status_code=400, detail="Failed to retrieve public key")
    
@app.get("/api/v1/get-backend-public-key")
async def get_backend_public_key():
    try:
        with open("clavesRSA/public_key.pem", "rb") as public_file:
            public_key = public_file.read()
            return {"public_key": public_key}
    except Exception as e:
        #Retrun http code 400
        raise HTTPException(status_code=400, detail="Failed to retrieve backend public key")