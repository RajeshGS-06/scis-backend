from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from fastapi.middleware.cors import CORSMiddleware

from model import UserCreate, Token, fake_users_db
from auth import hash_password, verify_password, create_access_token
from auth import SECRET_KEY, ALGORITHM

app = FastAPI()

# Crucial for React: Allow frontend to communicate with backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://scis-fsvj.vercel.app ", "http://localhost:5173", "http://localhost:3000"], # React ports
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

@app.post("/signup", status_code=status.HTTP_201_CREATED)
async def signup(user: UserCreate):
    if user.username in fake_users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    fake_users_db[user.username] = {
        "username": user.username,
        "hashed_password": hash_password(user.password)
    }
    return {"message": "User registered successfully"}

@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user_dict = fake_users_db.get(form_data.username)
    
    if not user_dict or not verify_password(form_data.password, user_dict["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(data={"sub": user_dict["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# --- Protected Route Example ---
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
    except JWTError:
        raise credentials_exception
        
    user = fake_users_db.get(username)
    if user is None:
        raise credentials_exception
    return user

@app.get("/profile")
async def get_profile(current_user: dict = Depends(get_current_user)):
    return {"username": current_user["username"], "status": "Active and authenticated"}