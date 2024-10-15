from typing import Union
from fastapi import FastAPI
from userLogIn import UserLogIn
from userSignUp import UserSignUp
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

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

@app.post("/api/v1/login")
async def login_view(login_request: LoginRequest):
    if UserLogIn(login_request.username, login_request.password).login():
        return {"login": "success"}
    else:
        return {"login": "failed"}

@app.post("/api/v1/signup")
async def signup_view(login_request: LoginRequest):
    if UserSignUp(login_request.username, login_request.password).signup():
        return {"signup": "success"}
    else:
        return {"signup": "failed"}
