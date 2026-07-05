from pydantic import BaseModel
from sqlalchemy import Column, Integer, String
from database import Base


# Defines what the React frontend must send to register/login
class UserCreate(BaseModel):
    fullname: str
    username: str
    password: str

# Defines the structure of the token sent back to React
class Token(BaseModel):
    access_token: str
    token_type: str

class DBUser(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    fullName = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)