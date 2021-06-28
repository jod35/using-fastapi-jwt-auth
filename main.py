from logging import currentframe
from os import access, stat
from fastapi import FastAPI,Depends,HTTPException,status
from fastapi.exceptions import HTTPException
from pydantic import BaseModel
from typing import List
from fastapi_jwt_auth import AuthJWT
from pydantic.networks import url_regex
from starlette.status import HTTP_401_UNAUTHORIZED


app=FastAPI()

class Settings(BaseModel):
    authjwt_secret_key:str='e8ae5c5d5cd7f0f1bec2303ad04a7c80f09f759d480a7a5faff5a6bbaa4078d0'


@AuthJWT.load_config
def get_config():
    return Settings()

class User(BaseModel):
    username:str
    email:str
    password:str

    class Config:
        schema_extra={
            "example":{
                "username":"john doe",
                "email":"johndoe@gmail.com",
                "password":"password"
            }
        }

class UserLogin(BaseModel):
    username:str
    password:str

    class Config:
        schema_extra={
            "example":{
                "username":"jonathan",
                "password":"password"
            }
        }



users=[]

@app.get("/")
def index():
    return {"message":"Hello"}

#create a user
@app.post('/signup',status_code=201)
def create_user(user:User):
    new_user={
        "username":user.username,
        "email":user.email,
        "password":user.password
    }

    users.append(new_user)

    return new_user

#getting all users
@app.get('/users',response_model=List[User])
def get_users():
    return users


@app.post('/login')
def login(user:UserLogin,Authorize:AuthJWT=Depends()):
    for u in users:
        if (u["username"]==user.username) and (u["password"]==user.password):
            access_token=Authorize.create_access_token(subject=user.username)
            refresh_token=Authorize.create_refresh_token(subject=user.username)

            return {"access_token":access_token,"refresh_token":refresh_token}

        raise HTTPException(status_code='401',detail="Invalid username or password")


@app.get('/protected')
def get_logged_in_user(Authorize:AuthJWT=Depends()):
    try:
        Authorize.jwt_required()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid token")


    current_user=Authorize.get_jwt_subject()

    return {"current_user":current_user}


@app.get('/new_token')
def create_new_token(Authorize:AuthJWT=Depends()):

    try:
        Authorize.jwt_refresh_token_required()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid token")

    current_user=Authorize.get_jwt_subject()

    access_token=Authorize.create_access_token(subject=current_user)

    return {"new_access_token":access_token}


@app.post('/fresh_login')
def fresh_login(user:UserLogin,Authorize:AuthJWT=Depends()):
    for u in users:
        if (u["username"]==user.username) and (u["password"]==user.password):
            fresh_token=Authorize.create_access_token(subject=user.username,fresh=True)

            return {"fresh_token":fresh_token}

    
        raise HTTPException(status=status.HTTP_401_UNAUTHORIZED,detail="Invalid Username or Password")



@app.get('/fresh_url')
def get_user(Authorize:AuthJWT=Depends()):
    try:
        Authorize.fresh_jwt_required()
    except Exception as e:
        raise HTTPException(status=HTTP_401_UNAUTHORIZED,detail="Invalid Token")

    current_user=Authorize.get_jwt_subject()

    return {"current_user":current_user}









            