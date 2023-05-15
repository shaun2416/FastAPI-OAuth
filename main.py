from fastapi import Depends, FastAPI, HTTPException, status, Response, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm 
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets
from typing import Annotated
from pydantic import BaseModel
from datetime import timedelta, datetime
from jose import JWTError, jwt 
from passlib.context import CryptContext 
import json


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


ENDPOINT_TO_SCOPE_MAPPING = {

    "/submit_restricted_scope":"write", 
    "/submit_restricted_scope_json": "write"

}


def validate_token_scope(endpoint, token):

    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    token_scope = payload.get("scope")

    if token_scope == "*":
        return True
    
    return ENDPOINT_TO_SCOPE_MAPPING[endpoint] in token_scope.split()


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


def validate_client_id_and_client_secret(client_id_bytes, client_secret_bytes):

    correct_client_id_bytes = b"stanleyjobson"
    is_correct_client_id = secrets.compare_digest(
        client_id_bytes, correct_client_id_bytes
    )

    correct_client_secret_bytes = b"swordfish"
    is_correct_client_secret = secrets.compare_digest(
        client_secret_bytes, correct_client_secret_bytes
    )

    if not (is_correct_client_id and is_correct_client_secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect client id or secret",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    return True





@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    
    print("Inside login_for_access_token")
    print(form_data)
    print(form_data.scopes)

    if form_data.client_id and form_data.client_secret:
        current_client_id_bytes = bytes(form_data.client_id, 'utf-8')
        current_client_secret_bytes = bytes(form_data.client_secret, 'utf-8')
        validate_client_id_and_client_secret(current_client_id_bytes, current_client_secret_bytes)


    scope = " ".join(form_data.scopes) if form_data.scopes else "*"

    user = authenticate_user(db, form_data.username, form_data.password)
    print(f"User : {user}")

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username/password", headers = {"WWW-Authenticate":"Bearer"})
    
    access_token_expires = timedelta(minutes = ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data = {"sub" : user.username, "scope": scope}, expires_delta=access_token_expires)

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



@app.post("/users/{user_id}/items/{item_id}")
async def save_user_item(
    user_id: int, item_id: str, queryParam1: str | None = None, queryParam2: str | None = None, 
    current_user: User = Depends(get_current_active_user)
):
    item = {"item_id": item_id, "owner_id": user_id}
    if queryParam1:
        item.update({"queryParam1": queryParam1})
    if not queryParam2:
        item.update(
            {"description": queryParam2}
        )
    item["currentUserFullName"] = current_user.full_name
    item["currentUserSkills"] = current_user.skills
    return item


@app.post("/employees/{user_id}/items/{item_id}")
async def save_user_item(request: Request,
    user_id: int, item_id: str, queryParam1: str | None = None, queryParam2: str | None = None, 
    current_user: User = Depends(get_current_active_user), 
    
):
    body = await request.body()
    item = {"item_id": item_id, "owner_id": user_id, "res": json.loads(body)}
    if queryParam1:
        item.update({"queryParam1": queryParam1})
    if not queryParam2:
        item.update(
            {"description": queryParam2}
        )
    item["currentUserFullName"] = current_user.full_name
    item["currentUserSkills"] = current_user.skills
    return item





@app.post("/submit")
async def submit(request: Request, current_user: User = Depends(get_current_active_user)):
    content_type = request.headers['Content-Type']
    if content_type == 'application/xml':
        body = await request.body()
        return Response(content=body, media_type="application/xml")
    else:
        raise HTTPException(status_code=400, detail=f'Content type {content_type} not supported')



@app.post("/submit_restricted_scope")
async def submit(request: Request, current_user: User = Depends(get_current_active_user), token: str = Depends(oauth2_scheme)):

    if not validate_token_scope("/submit_restricted_scope", token):
        raise HTTPException(status_code=403, detail=f'Token with write scope is required.')

    content_type = request.headers['Content-Type']
    if content_type == 'application/xml':
        body = await request.body()
        return Response(content=body, media_type="application/xml")
    else:
        raise HTTPException(status_code=400, detail=f'Content type {content_type} not supported')


@app.post("/submit_restricted_scope_json")
async def submit(request: Request, current_user: User = Depends(get_current_active_user), token: str = Depends(oauth2_scheme)):

    if not validate_token_scope("/submit_restricted_scope", token):
        raise HTTPException(status_code=403, detail=f'Token with write scope is required.')

    content_type = request.headers['Content-Type']
    if content_type == 'application/json':
        body = await request.body()
        return Response(content=body, media_type="application/json")
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


@app.post("/token_password_grant_type_with_client_creds_as_basic_auth_header", response_model=Token)
async def login_for_access_token_with_client_credentials_in_basic_auth_header(username: Annotated[str, Depends(get_current_username)], form_data: OAuth2PasswordRequestForm = Depends()):
    
    print("Inside login_for_access_token_with_client_credentials_in_basic_auth_header")
    print(form_data)
    print(form_data.scopes)

    scope = " ".join(form_data.scopes) if form_data.scopes else "*"

    user = authenticate_user(db, form_data.username, form_data.password)
    print(f"User : {user}")

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username/password", headers = {"WWW-Authenticate":"Bearer"})
    
    access_token_expires = timedelta(minutes = ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data = {"sub" : user.username, "scope": scope}, expires_delta=access_token_expires)

    print(access_token)

    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me")
def read_current_user(username: Annotated[str, Depends(get_current_username)]):
    return {"username": username}


@app.post("/submit_basicAuth")
async def submit(request: Request, username: Annotated[str, Depends(get_current_username)]):
    content_type = request.headers['Content-Type']
    if content_type == 'application/xml':
        body = await request.body()
        return Response(content=body, media_type="application/xml")
    else:
        raise HTTPException(status_code=400, detail=f'Content type {content_type} not supported')



# pwd_hash = get_password_hash("shaunak1234") 
# print(pwd_hash)









