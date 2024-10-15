from typing import Union
from fastapi import FastAPI
from userLogIn import UserLogIn
from userSignUp import UserSignUp

app = FastAPI()

@app.get("/api/v1/hello")
def read_root():
    return {"Hello": "World"}

@app.post("/api/v1/login")
def login_view(username: str, password: str):
    if UserLogIn(username, password).login():
        return {"login": "success"}
    else:
        return {"login": "failed"}

@app.post("/api/v1/signup")
def signup_view(username: str, password: str):
    if UserSignUp(username, password).signup():
        return {"signup": "success"}
    else:
        return {"signup": "failed"}
