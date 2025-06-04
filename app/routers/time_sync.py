from fastapi import APIRouter
import datetime

router = APIRouter()

@router.get("/server-time")
async def get_server_time():
    """Get current server time in UTC timestamp format"""
    current_time = datetime.datetime.now(datetime.timezone.utc)
    return {
        "timestamp": int(current_time.timestamp()),
        "utc_time": current_time.isoformat()
    } 