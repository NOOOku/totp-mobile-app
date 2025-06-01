from fastapi import APIRouter, Depends, HTTPException, status, Header
from sqlalchemy.orm import Session
from .. import crud, models, schemas, utils
from ..database import get_db
from pydantic import BaseModel
import logging
from typing import Optional

logger = logging.getLogger(__name__)

router = APIRouter()

class MobileLoginRequest(BaseModel):
    short_secret: str

@router.post("/mobile/login")
async def mobile_login(
    request: MobileLoginRequest,
    db: Session = Depends(get_db),
    authorization: Optional[str] = Header(None)
):
    """
    Вход в мобильное приложение по короткому ключу.
    Возвращает полный секрет для генерации TOTP.
    """
    logger.info("Получен запрос на мобильный вход")
    logger.info(f"Authorization header: {authorization}")
    logger.info(f"Короткий ключ: {request.short_secret}")
    
    if not authorization or not authorization.startswith("Bearer "):
        logger.error("Отсутствует или неверный формат токена авторизации")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization token"
        )
    
    totp_secret = crud.get_totp_by_short_secret(db, request.short_secret)
    if not totp_secret:
        logger.error(f"Не найден TOTP секрет для короткого ключа: {request.short_secret}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid short secret"
        )
    
    logger.info(f"Найден TOTP секрет для пользователя {totp_secret.user_id}")
    return {
        "full_secret": totp_secret.secret,
        "user_id": totp_secret.user_id
    } 