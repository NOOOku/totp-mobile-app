from fastapi import APIRouter
import datetime
import time

router = APIRouter()

@router.get("/server-time")
async def get_server_time():
    """Get current server time in UTC timestamp format"""
    current_timestamp = int(time.time())
    current_time = datetime.datetime.fromtimestamp(current_timestamp, tz=datetime.timezone.utc)
    return {
        "timestamp": current_timestamp,
        "utc_time": current_time.isoformat()
    } 