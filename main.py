from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from datetime import datetime, timedelta
from jose import JWTError, jwt

# HARSHING PASSWORD
from passlib.context import CryptContext
from models import UserInDB, TokenData, Token, User, CreateUser
from dotenv import load_dotenv
import os
load_dotenv()




SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))


pwd_context = CryptContext(schemes=['bcrypt'], deprecated="auto")
oauth_2_scheme = OAuth2PasswordBearer(tokenUrl="token")



db = {
    "test":{
        "username": "test",
        "full_name": "Test first",
        "email": "t@gmail.com",
        "hashed_password": "$2b$12$2LdLbIGcAx2tbXRuy75inOAd25axymeWcZboV1xAZY0IgMuHFsT3m",
        "disabled": True,
    }
}


app = FastAPI()


@app.get("/")
async def test():
    return {"Response":"success"}

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    """Get a user from DB with a given username."""
    if username in db:
        user_data = db[username]
        return UserInDB(**user_data)
    
def authenticate_user(db, username: str, password: str):
    """Authenticate a user."""
    user = get_user(db, username)

    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False

    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """Creaate/Generate an access token to a user."""
    
    # copy the user data
    to_encode = data.copy()

    # if there is a diff btw the currrent time and when we want the token to expire 
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes = 15)

    # to update our user dict and add "exp" propriety with a expire time 
    to_encode.update({"exp":expire})

    # generate an access token
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    #  return the token
    return encoded_jwt


# Depends(oauth2_scheme)parse the token we pass and give us access to it
async def get_current_user(token: str = Depends(oauth_2_scheme)):
    """Authenticate a user token to check if he/she has access."""

    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                                         detail="Could not validate credentials",
                                           headers={"WWW-Authenticate": "Bearer"}
                                           )

    try:
        # we decode the token to get the username from it
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')

        # check if there is a username associated with the token
        if username is None:
            raise credential_exception
        
        # we get the token data associated with the username
        token_data = TokenData(username=username)

    except JWTError:
        raise credential_exception
    
    # make sure that the user is in the database
    user = get_user(db, username=token_data.username)

    if user is None:
        raise credential_exception
    
    return user


async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
    """To check if a user is disable/active from login."""

    if current_user.disabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    
    return current_user 


# this route configure/ste 'oauth_2_scheme = OAuth2PasswordBearer(tokenUrl="token")'
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """Generate a token when we loginsingin with valid credentials."""

    #  First it authenticate the user
    user = authenticate_user(db, form_data.username, form_data.password)
    # check if the authentication has return a user
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                            detail="Incorrect username or password.",
                            headers={"WWW-Authenticate":"Bearer"})
    
    # 
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    access_token = create_access_token(data={'sub': user.username}, 
                                       expires_delta=access_token_expires)

    return {"access_token": access_token, "token_type": "Bearer"}


@app.get("/users/me/")
async def read_users_me(current_user: User = Depends(get_current_active_user)) -> User:
    return current_user


@app.get("/users/me/items")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{
        "item_id":1,
        "owner":current_user
        }]


@app.post("/create")
async def create_user(userData: CreateUser):
    """To create a user."""

    if not userData.username or not userData.full_name or not userData.email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
                            detail="Please fill the form correctly.")
    if len(userData.username) < 3 or len(userData.full_name) < 3:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
                    detail="Please the length of username and full name must be greater than 3.")
    
    if "@gmail.com" not in userData.email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
                    detail="Please your email must contain @gmail.com.")
    
    if userData.password != userData.confirm_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Unmatch passwords !! Please your password and confirm passwordmust be the same.")

    # query to db for a unique username
    for user in db:
        
        if user == userData.username:    
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, 
                detail="Username already exist!! Please choose another username.")
        
    db[userData.username] = {
        "username": userData.username,
        "full_name": userData.full_name,
        "email": userData.email,
        "hashed_password": get_password_hash(userData.password),
        "disabled":False,
    }

    return db[userData.username]
    
# pwd = get_password_hash("test1234")
# print("here: ",pwd)