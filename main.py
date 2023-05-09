from fastapi import Depends, FastAPI, HTTPException, status, Response, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm 
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets
from typing import Annotated
from pydantic import BaseModel
from datetime import timedelta, datetime
from jose import JWTError, jwt 
from passlib.context import CryptContext 


SECRET_KEY = "6B58703273357638792F423F4528482B4D6250655368566D597133743677397A" 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30 


db = {
    "Shaunak" : {
        "username": "Shaunak", 
        "full_name": "Shaunak Chakraborty", 
        "email" : "shaunak@gmail.com", 
        "hashed_password": "$2b$12$v/clkWbhpUNFLm7nZzEhPeLZCG0oKHQDfqWXr7v9eTfB1QwN9FQx2", 
        "disabled": False, 
        "skills": [
            {
                "id": 1001, 
                "name": "AWS",
                "is_certified": True
            }, 
            {
                "id": 1002, 
                "name": "QA",
                "is_certified": False
            }, 
            {
                "id": 1003, 
                "name": "Data Analytics",
                "is_certified": False
            }
        ]
    }
}

class Token(BaseModel):
    access_token: str 
    token_type: str 

class TokenData(BaseModel):
    username: str or None = None 

class User(BaseModel):
    username: str 
    email : str or None = None 
    full_name: str or None = None 
    disabled : bool or None = None
    skills: list = [] 

class UserInDB(User):
    hashed_password: str 


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    if username in db:
        user_data = db[username]
        return UserInDB(**user_data)


def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False 
    if not verify_password(password, user.hashed_password):
        return False 
    return user 

def create_access_token(data: dict, expires_delta: timedelta or None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta 
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credential_exception = HTTPException(status_code= status.HTTP_401_UNAUTHORIZED, detail = "Could not validate credentials", headers = {"WWW-Authenticate":"Bearer"})

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credential_exception  
        token_data = TokenData(username=username)


    except JWTError:
        raise credential_exception
    
    user = get_user(db, username = token_data.username)
    if user is None: 
        raise credential_exception 
    
    return user


async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):

    if current_user.disabled:
        raise HTTPException(status_code=400, detail = "Inactive user")
    
    return current_user 

app = FastAPI()

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    
    print("Inside login_for_access_token")
    user = authenticate_user(db, form_data.username, form_data.password)
    print(f"User : {user}")

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username/password", headers = {"WWW-Authenticate":"Bearer"})
    
    access_token_expires = timedelta(minutes = ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data = {"sub" : user.username}, expires_delta=access_token_expires)

    print(access_token)

    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model = User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user 


@app.get("/users/me/items")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return { "res": [{"item_id": 1, "owner":current_user}]  }





@app.get("/users/{user_id}/items/{item_id}")
async def read_user_item(
    user_id: int, item_id: str, q: str | None = None, short: bool = False
):
    item = {"item_id": item_id, "owner_id": user_id}
    if q:
        item.update({"q": q})
    if not short:
        item.update(
            {"description": "This is an amazing item that has a long description"}
        )
    return item


@app.post("/submit")
async def submit(request: Request, current_user: User = Depends(get_current_active_user)):
    content_type = request.headers['Content-Type']
    if content_type == 'application/xml':
        body = await request.body()
        return Response(content=body, media_type="application/xml")
    else:
        raise HTTPException(status_code=400, detail=f'Content type {content_type} not supported')





security = HTTPBasic()


def get_current_username(
    credentials: Annotated[HTTPBasicCredentials, Depends(security)]
):
    current_username_bytes = credentials.username.encode("utf8")
    correct_username_bytes = b"stanleyjobson"
    is_correct_username = secrets.compare_digest(
        current_username_bytes, correct_username_bytes
    )
    current_password_bytes = credentials.password.encode("utf8")
    correct_password_bytes = b"swordfish"
    is_correct_password = secrets.compare_digest(
        current_password_bytes, correct_password_bytes
    )
    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


@app.get("/users/me")
def read_current_user(username: Annotated[str, Depends(get_current_username)]):
    return {"username": username}


@app.post("/submit")
async def submit(request: Request, username: Annotated[str, Depends(get_current_username)]):
    content_type = request.headers['Content-Type']
    if content_type == 'application/xml':
        body = await request.body()
        return Response(content=body, media_type="application/xml")
    else:
        raise HTTPException(status_code=400, detail=f'Content type {content_type} not supported')



# pwd_hash = get_password_hash("shaunak1234") 
# print(pwd_hash)









