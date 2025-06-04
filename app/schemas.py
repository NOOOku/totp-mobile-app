from pydantic import BaseModel, EmailStr

class UserBase(BaseModel):
    username: str
    email: EmailStr

class UserCreate(UserBase):
    password: str

class TOTPSecretBase(BaseModel):
    secret: str
    short_secret: str
    is_verified: bool = False

class TOTPSecretCreate(TOTPSecretBase):
    user_id: int

class TOTPSecret(TOTPSecretBase):
    id: int
    user_id: int

    class Config:
        from_attributes = True

class User(UserBase):
    id: int
    is_active: bool
    totp_secret: TOTPSecret | None = None

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user: User
    full_secret: str
    user_id: int

class TokenData(BaseModel):
    username: str | None = None 