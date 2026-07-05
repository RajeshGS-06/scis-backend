import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Default to local SQLite database if no cloud database URL is provided
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sql_app.db")

# Fix Render/Heroku PostgreSQL URLs which use 'postgres://' instead of 'postgresql://'
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# SQLite requires an extra argument; PostgreSQL does not
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Dependency to get database sessions in our routes
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()