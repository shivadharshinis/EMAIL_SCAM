from fastapi import APIRouter, HTTPException, status

from app.auth import create_demo_token
from app.core.config import get_settings
from app.schemas.auth import TokenRequest, TokenResponse

router = APIRouter()


@router.post("/auth/token", response_model=TokenResponse)
async def issue_demo_token(request: TokenRequest) -> TokenResponse:
    settings = get_settings()
    if not settings.report_auth_required:
        raise HTTPException(status_code=404, detail="Demo authentication is disabled.")
    if request.username != settings.demo_username or request.password != settings.demo_password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")
    return TokenResponse(access_token=create_demo_token(request.username))
