import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# By default, use SQLite locally so it works without Docker or external DBs.
# To use Postgres, set DATABASE_URL="postgresql://user:password@localhost/dbname"
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./honeypot.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
