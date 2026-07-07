from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from jose import jwt, JWTError
from dotenv import load_dotenv
import aiosmtplib
from email.message import EmailMessage
import os

load_dotenv()

# Security settings
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
EMAIL_VERIFICATION_EXPIRE_HOURS = 24

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD")
EMAIL_FROM_NAME = os.getenv("EMAIL_FROM_NAME", "SCIS")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_email_verification_token(email: str) -> str:
    """Creates a short-lived JWT used only for email verification links."""
    expire = datetime.now(timezone.utc) + timedelta(hours=EMAIL_VERIFICATION_EXPIRE_HOURS)
    payload = {"sub": email, "purpose": "email_verification", "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_email_verification_token(token: str):
    """Returns the email if the token is valid and meant for verification, else None."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("purpose") != "email_verification":
            return None
        return payload.get("sub")
    except JWTError:
        return None


async def send_verification_email(to_email: str, full_name: str, token: str, frontend_url: str):
    """Sends a verification email with a link the user clicks to confirm their account."""
    verify_link = f"{frontend_url}/verify-email?token={token}"

    message = EmailMessage()
    message["From"] = f"{EMAIL_FROM_NAME} <{EMAIL_ADDRESS}>"
    message["To"] = to_email
    message["Subject"] = "Verify your SCIS account"
    message.set_content(
        f"Hi {full_name},\n\n"
        f"Please verify your email by clicking this link:\n{verify_link}\n\n"
        f"This link expires in {EMAIL_VERIFICATION_EXPIRE_HOURS} hours.\n\n"
        f"If you didn't sign up for SCIS, you can ignore this email."
    )

    await aiosmtplib.send(
        message,
        hostname="smtp.gmail.com",
        port=587,
        start_tls=True,
        username=EMAIL_ADDRESS,
        password=EMAIL_APP_PASSWORD,
    )