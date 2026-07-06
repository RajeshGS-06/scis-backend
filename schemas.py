from pydantic import BaseModel, EmailStr, Field, field_validator
import re

class UserCreate(BaseModel):
    fullName: str
    email: EmailStr
    password: str = Field(min_length=8)

@field_validator("password")
@classmethod
def validate_password(cls, value):
    # Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character
    if not re.fullmatch(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', value):
        raise ValueError("Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character, and be at least 8 characters long.")
    return value

class Token(BaseModel):
    access_token: str
    token_type: str