from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional
from pydantic import BaseModel, EmailStr
import secrets

app = FastAPI()

# Secret key to encode the JWT (use a more secure and secret key for production)
SECRET_KEY = secrets.token_hex(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing context
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# User models
class User(BaseModel):
    username: EmailStr
    full_name: str
    hashed_password: str
    disabled: Optional[bool] = False
    phone_no: Optional[str] = None

class UserInDB(User):
    pass

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    name: str
    phone_no: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

# Mock database
fake_users_db = {}

# Password hashing and verification functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# User retrieval function
def get_user(db, email: str):
    if email in db:
        user_dict = db[email]
        return UserInDB(**user_dict)

# Authentication function
def authenticate_user(email: str, password: str):
    user = get_user(fake_users_db, email)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

# Create JWT access token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Register endpoint
@app.post("/register")
async def register(user: UserRegister):
    if user.email in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )
    hashed_password = get_password_hash(user.password)
    fake_users_db[user.email] = {
        "username": user.email,
        "full_name": user.name,
        "hashed_password": hashed_password,
        "disabled": False,
        "phone_no": user.phone_no,
    }
    return {
        "message": "User registered successfully",
        "status_code": 200,
    }

# Login endpoint
@app.post("/login")
async def login_for_access_token(user_login: UserLogin):
    user = authenticate_user(user_login.email, user_login.password)
    if not user:
        return {
            "message": "Incorrect email or password",
            "status_code": 401,
        }
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {
        "auth_token": access_token,
        "status_code": 200,
    }

# Protected route using JWT token
@app.get("/users/me")
async def read_users_me(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, email)
    if user is None:
        raise credentials_exception
    return user

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
