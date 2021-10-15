import json
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
with open("menu.json", "r") as read_file:
    data = json.load(read_file)
app = FastAPI()



# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "6efd7efeeaa3a32e7725ca4e9bd6a3f08a931b2be8d7a773f952d5115cbe4d40"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str


password = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")



def verify_password(input_password, hashed_password):
    return password.verify(input_password, hashed_password)


def get_hashed_password(password):
    return password.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(data_account, username: str, password: str):
    user = get_user(data_account, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{"item_id": "Foo", "owner": current_user.username}]

class Item(BaseModel):
    id: int
    name: str
    
# Get spesific value operation
@app.get("/menu/{item_id}")
async def read_menu(item_id : int):
    for menu_item in data['menu']:
        if menu_item['id'] == item_id:
            return menu_item
    raise HTTPException(
        status_code = 404, detail=f'Item not found'
    )

# Get all value operation
@app.get("/men/u")
async def show_menu():
    return data["menu"]

# Update operation
@app.put("/menu/")
async def update_menu(item:Item):
    chosen_id = -1
    for i in range (len(data["menu"])):
        if (data["menu"][i]["id"] == item.id):
            chosen_id = i
    if chosen_id != -1:
        data["menu"][chosen_id]["name"] = item.name
        with open("menu.json","w") as updateFile:
            json.dump(data, updateFile)
        return item
    raise HTTPException(
        status_code = 404, detail=f'Item not found'
    )


# Post operation

@app.post("/menu")
async def add_menu(item:Item):
    data["menu"].append({"id":item.id, "name":item.name})
    with open("menu.json","w") as postFile:
        json.dump(data, postFile)
    return item

# Delete operation

@app.delete("/menu/{item_id}")
async def delete_menu(item_id:int):
    chosen_id = 0
    for menu_item in data["menu"]:
        if menu_item["id"] == item_id:
            del data["menu"][chosen_id]
            with open("menu.json","w") as deleteFile:
                json.dump(data, deleteFile)
            return menu_item
        chosen_id += 1
    raise HTTPException(
        status_code = 404, detail=f'Item not found'
    )
