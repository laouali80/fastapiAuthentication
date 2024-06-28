from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str | None = None
    full_name: str | None = None
    email:str | None = None
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str 

class CreateUser(BaseModel):
    username: str
    full_name: str
    email: str
    password: str
    confirm_password: str