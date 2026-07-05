from pydantic import BaseModel

class UserCreate(BaseModel):
    fullName: str
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str