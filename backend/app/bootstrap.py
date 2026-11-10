from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.models import User
from app.schemas import Credentials
from app.security import hash_password


DEMO_ACCOUNT_EMAILS = (
    ("admin@trustvault.com", True),
    ("owner@trustvault.com", False),
    ("viewer@trustvault.com", False),
)


def _create_user_if_missing(
    session_factory: sessionmaker[Session],
    email: str,
    password: str,
    *,
    is_admin: bool,
) -> bool:
    credentials = Credentials(email=email, password=password)
    with session_factory() as db:
        existing = db.scalar(select(User).where(User.email == credentials.email))
        if existing is not None:
            return False

        db.add(
            User(
                id=str(uuid4()),
                email=credentials.email,
                display_name=str(credentials.email),
                password_hash=hash_password(credentials.password),
                is_admin=is_admin,
            )
        )
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            if db.scalar(select(User).where(User.email == credentials.email)) is not None:
                return False
            raise
    return True


def bootstrap_admin(
    session_factory: sessionmaker[Session], email: str, password: str
) -> bool:
    return _create_user_if_missing(
        session_factory, email, password, is_admin=True
    )


def bootstrap_demo_accounts(
    session_factory: sessionmaker[Session],
    admin_password: str,
    owner_password: str,
    viewer_password: str,
) -> tuple[int, int]:
    passwords = (admin_password, owner_password, viewer_password)
    created = sum(
        _create_user_if_missing(
            session_factory,
            email,
            password,
            is_admin=is_admin,
        )
        for (email, is_admin), password in zip(DEMO_ACCOUNT_EMAILS, passwords)
    )
    return created, len(DEMO_ACCOUNT_EMAILS) - created
