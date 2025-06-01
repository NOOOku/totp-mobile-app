from sqlalchemy import Boolean, Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    totp_secret = relationship("TOTPSecret", back_populates="user", uselist=False)

class TOTPSecret(Base):
    __tablename__ = "totp_secrets"

    id = Column(Integer, primary_key=True, index=True)
    secret = Column(String)  # полный секретный ключ
    short_secret = Column(String, unique=True, index=True)  # короткий ключ для пользователя
    is_verified = Column(Boolean, default=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User", back_populates="totp_secret") 