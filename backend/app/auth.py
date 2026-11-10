import hmac
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import Settings
from app.database import get_db
from app.models import AuthSession, User
from app.schemas import Credentials, CsrfToken, UserRead
from app.security import (
    burn_password_verification,
    hash_password,
    hash_session_token,
    new_csrf_token,
    new_session_token,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["authentication"])


def require_csrf(request: Request) -> None:
    cookie_token = request.cookies.get("trustvault_csrf")
    header_token = request.headers.get("X-CSRF-Token")
    if not cookie_token or not header_token or not hmac.compare_digest(
        cookie_token, header_token
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token"
        )


def _set_csrf_cookie(response: Response, request: Request) -> str:
    token = new_csrf_token()
    settings: Settings = request.app.state.settings
    response.set_cookie(
        "trustvault_csrf",
        token,
        httponly=False,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )
    return token


def _set_session_cookie(response: Response, request: Request, token: str) -> None:
    settings: Settings = request.app.state.settings
    response.set_cookie(
        settings.session_cookie_name,
        token,
        max_age=settings.session_lifetime_seconds,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )


@router.get("/csrf", response_model=CsrfToken)
def get_csrf_token(request: Request, response: Response) -> CsrfToken:
    token = request.cookies.get("trustvault_csrf") or new_csrf_token()
    settings: Settings = request.app.state.settings
    response.set_cookie(
        "trustvault_csrf",
        token,
        httponly=False,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )
    return CsrfToken(csrf_token=token)


@router.post(
    "/register",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_csrf)],
)
def register(credentials: Credentials, db: Session = Depends(get_db)) -> User:
    existing_user = db.scalar(select(User).where(User.email == credentials.email))
    if existing_user:
        raise HTTPException(status_code=409, detail="Email is already registered")

    user = User(
        id=str(uuid4()),
        email=credentials.email,
        display_name=credentials.display_name or str(credentials.email),
        password_hash=hash_password(credentials.password),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Email is already registered") from None
    db.refresh(user)
    return user


@router.post(
    "/login",
    response_model=UserRead,
    dependencies=[Depends(require_csrf)],
)
def login(
    credentials: Credentials,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> User:
    user = db.scalar(select(User).where(User.email == credentials.email))
    if user is None:
        burn_password_verification(credentials.password)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not verify_password(credentials.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if user.disabled_at is not None:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    now = datetime.now(timezone.utc)
    token = new_session_token()
    session = AuthSession(
        id=str(uuid4()),
        user_id=user.id,
        token_hash=hash_session_token(token),
        expires_at=now
        + timedelta(seconds=request.app.state.settings.session_lifetime_seconds),
    )
    db.add(session)
    db.commit()

    _set_session_cookie(response, request, token)
    _set_csrf_cookie(response, request)
    return user


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_csrf)],
)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> Response:
    settings: Settings = request.app.state.settings
    token = request.cookies.get(settings.session_cookie_name)
    if token:
        session = db.scalar(
            select(AuthSession).where(
                AuthSession.token_hash == hash_session_token(token),
                AuthSession.revoked_at.is_(None),
            )
        )
        if session:
            session.revoked_at = datetime.now(timezone.utc)
            db.commit()

    response.delete_cookie(
        settings.session_cookie_name,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )
    _set_csrf_cookie(response, request)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


def get_current_user(
    request: Request, db: Session = Depends(get_db)
) -> User:
    settings: Settings = request.app.state.settings
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")

    now = datetime.now(timezone.utc)
    session = db.scalar(
        select(AuthSession)
        .where(
            AuthSession.token_hash == hash_session_token(token),
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > now,
        )
    )
    if session is None or session.user.disabled_at is not None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return session.user


@router.get("/me", response_model=UserRead)
def get_me(user: User = Depends(get_current_user)) -> User:
    return user
