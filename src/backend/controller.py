from typing import Union
from fastapi import FastAPI
from backend.userLogIn import UserLogIn

app = FastAPI()

@app.get("/api/v1/hello")
def read_root():
    return {"Hello": "World"}

@app.get("/api/v1/login")
def login_view():
    UserLogIn("username", "password").login()
    return {"login": "success"}

@app.get("/api/v1/signup")
def signup_view():
    return {"signup": "success"}
