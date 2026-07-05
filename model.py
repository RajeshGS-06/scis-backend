from pydantic import BaseModel

# Defines what the React frontend must send to register/login
class UserCreate(BaseModel):
    fullname: str
    username: str
    password: str

# Defines the structure of the token sent back to React
class Token(BaseModel):
    access_token: str
    token_type: str

# Fake in-memory database (replace with PostgreSQL/MongoDB later)
fake_users_db = {}