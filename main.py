from dotenv import load_dotenv
load_dotenv()
from fastapi import FastAPI, Depends, HTTPException, Request, status, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
import os

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

import model
import schemas
from database import engine, get_db
from auth import (
    hash_password, verify_password, create_access_token, SECRET_KEY, ALGORITHM,
    create_email_verification_token, decode_email_verification_token, send_verification_email
)

# Create the database tables automatically if they don't exist yet
model.Base.metadata.create_all(bind=engine)

app = FastAPI()

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

frontend_urls = os.getenv("FRONTEND_URL", "http://localhost:5173")
allow_origins = [url.strip() for url in frontend_urls.split(",")]
FRONTEND_URL_FOR_LINKS = allow_origins[0]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 5


@app.post("/signup", status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def signup(request: Request, background_tasks: BackgroundTasks, user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(model.DBUser).filter(model.DBUser.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = model.DBUser(
        fullName=user.fullName,
        email=user.email,
        hashed_password=hash_password(user.password)
    )

    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Error occurred while registering user")

    token = create_email_verification_token(new_user.email)
    background_tasks.add_task(
        send_verification_email, new_user.email, new_user.fullName, token, FRONTEND_URL_FOR_LINKS
    )

    return {"message": "User registered successfully. Please check your email to verify your account."}


@app.post("/login", response_model=schemas.Token)
@limiter.limit("5/minute")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    db_user = db.query(model.DBUser).filter(model.DBUser.email == form_data.username).first()

    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if db_user.locked_until and db_user.locked_until > datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Account locked. Try again after {db_user.locked_until.strftime('%H:%M:%S')} UTC."
        )

    if not verify_password(form_data.password, db_user.hashed_password):
        db_user.failed_login_attempts += 1
        if db_user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            db_user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            db_user.failed_login_attempts = 0
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not db_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Please verify your email before logging in."
        )

    db_user.failed_login_attempts = 0
    db_user.locked_until = None
    db.commit()

    access_token = create_access_token(data={"sub": db_user.email})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/verify-email")
async def verify_email(token: str, db: Session = Depends(get_db)):
    email = decode_email_verification_token(token)
    if not email:
        raise HTTPException(status_code=400, detail="Invalid or expired verification link")

    db_user = db.query(model.DBUser).filter(model.DBUser.email == email).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    if db_user.is_verified:
        return {"message": "Email already verified"}

    db_user.is_verified = True
    db.commit()
    return {"message": "Email verified successfully"}


@app.post("/resend-verification")
@limiter.limit("3/minute")
async def resend_verification(request: Request, background_tasks: BackgroundTasks, email: schemas.EmailRequest, db: Session = Depends(get_db)):
    db_user = db.query(model.DBUser).filter(model.DBUser.email == email.email).first()

    if db_user and not db_user.is_verified:
        token = create_email_verification_token(db_user.email)
        background_tasks.add_task(
            send_verification_email, db_user.email, db_user.fullName, token, FRONTEND_URL_FOR_LINKS
        )

    return {"message": "If an account with that email exists and isn't verified, a new link has been sent."}


async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(model.DBUser).filter(model.DBUser.email == email).first()
    if user is None:
        raise credentials_exception
    return user


@app.get("/profile")
async def get_profile(current_user: model.DBUser = Depends(get_current_user)):
    return {"username": current_user.email, "fullName": current_user.fullName, "status": "Active"}