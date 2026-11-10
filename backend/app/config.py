import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


def _validate_frontend_origin(origin: str) -> None:
    parsed = urlsplit(origin)
    if (
        origin == "*"
        or parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "TRUSTVAULT_FRONTEND_ORIGIN must contain explicit HTTP(S) origins only"
        )


def vercel_blob_credentials_available() -> bool:
    read_write_token = os.getenv("BLOB_READ_WRITE_TOKEN", "").strip()
    if read_write_token:
        return True
    return (
        os.getenv("VERCEL") == "1"
        and bool(os.getenv("BLOB_STORE_ID", "").strip())
    )


@dataclass(frozen=True)
class Settings:
    database_url: str = "sqlite:///./trustvault-dev.db"
    storage_directory: str = str(Path(__file__).resolve().parents[2] / "private_storage")
    storage_provider: str = "filesystem"
    session_cookie_name: str = "trustvault_session"
    session_lifetime_seconds: int = 12 * 60 * 60
    cookie_secure: bool = True
    cookie_samesite: str = "lax"
    frontend_origins: tuple[str, ...] = ()
    bootstrap_admin_email: str | None = None
    bootstrap_admin_password: str | None = None
    seed_demo_accounts: bool = False
    demo_admin_password: str | None = None
    demo_owner_password: str | None = None
    demo_viewer_password: str | None = None

    def __post_init__(self) -> None:
        if not self.database_url.startswith("sqlite:"):
            raise ValueError("TRUSTVAULT_DATABASE_URL must use SQLite")
        if self.session_lifetime_seconds <= 0:
            raise ValueError("TRUSTVAULT_SESSION_LIFETIME_SECONDS must be positive")
        if not self.session_cookie_name or any(
            character in self.session_cookie_name for character in ";, \t\r\n"
        ):
            raise ValueError("TRUSTVAULT_SESSION_COOKIE_NAME is invalid")
        if not self.storage_provider:
            raise ValueError("TRUSTVAULT_STORAGE_PROVIDER must not be empty")
        if self.cookie_samesite not in {"lax", "strict", "none"}:
            raise ValueError(
                "TRUSTVAULT_COOKIE_SAMESITE must be lax, strict, or none"
            )
        if self.cookie_samesite == "none" and not self.cookie_secure:
            raise ValueError("SameSite=None cookies require Secure cookies")
        for origin in self.frontend_origins:
            _validate_frontend_origin(origin)
        if (self.bootstrap_admin_email is None) != (
            self.bootstrap_admin_password is None
        ):
            raise ValueError(
                "Both TRUSTVAULT_BOOTSTRAP_ADMIN_EMAIL and "
                "TRUSTVAULT_BOOTSTRAP_ADMIN_PASSWORD must be set together"
            )
        if self.bootstrap_admin_password is not None and not (
            12 <= len(self.bootstrap_admin_password) <= 128
        ):
            raise ValueError(
                "TRUSTVAULT_BOOTSTRAP_ADMIN_PASSWORD must be 12 to 128 characters"
            )
        demo_passwords = (
            self.demo_admin_password,
            self.demo_owner_password,
            self.demo_viewer_password,
        )
        if self.seed_demo_accounts and not all(
            password is not None for password in demo_passwords
        ):
            raise ValueError(
                "Demo-account seeding requires all three demo passwords"
            )
        if not self.seed_demo_accounts and any(
            password is not None for password in demo_passwords
        ):
            raise ValueError(
                "Enable demo-account seeding to configure demo passwords"
            )
        if any(
            password is not None and not 12 <= len(password) <= 128
            for password in demo_passwords
        ):
            raise ValueError("Demo account passwords must be 12 to 128 characters")

    @classmethod
    def from_environment(cls) -> "Settings":
        secure_value = os.getenv("TRUSTVAULT_COOKIE_SECURE", "true").strip().lower()
        if secure_value not in {"true", "false"}:
            raise ValueError("TRUSTVAULT_COOKIE_SECURE must be true or false")
        seed_demo_accounts = os.getenv(
            "TRUSTVAULT_SEED_DEMO_ACCOUNTS", "false"
        ).strip().lower()
        if seed_demo_accounts not in {"true", "false"}:
            raise ValueError("TRUSTVAULT_SEED_DEMO_ACCOUNTS must be true or false")
        frontend_origins = tuple(
            origin.strip().rstrip("/")
            for origin in os.getenv("TRUSTVAULT_FRONTEND_ORIGIN", "").split(",")
            if origin.strip()
        )
        return cls(
            database_url=os.getenv(
                "TRUSTVAULT_DATABASE_URL", "sqlite:///./trustvault-dev.db"
            ),
            storage_directory=os.getenv(
                "TRUSTVAULT_STORAGE_DIRECTORY",
                str(Path(__file__).resolve().parents[2] / "private_storage"),
            ),
            storage_provider=os.getenv(
                "TRUSTVAULT_STORAGE_PROVIDER", "filesystem"
            ).strip(),
            session_cookie_name=os.getenv(
                "TRUSTVAULT_SESSION_COOKIE_NAME", "trustvault_session"
            ),
            session_lifetime_seconds=int(
                os.getenv("TRUSTVAULT_SESSION_LIFETIME_SECONDS", str(12 * 60 * 60))
            ),
            cookie_secure=secure_value == "true",
            cookie_samesite=os.getenv(
                "TRUSTVAULT_COOKIE_SAMESITE", "lax"
            ).strip().lower(),
            frontend_origins=frontend_origins,
            bootstrap_admin_email=os.getenv("TRUSTVAULT_BOOTSTRAP_ADMIN_EMAIL")
            or None,
            bootstrap_admin_password=os.getenv("TRUSTVAULT_BOOTSTRAP_ADMIN_PASSWORD")
            or None,
            seed_demo_accounts=seed_demo_accounts == "true",
            demo_admin_password=os.getenv("TRUSTVAULT_DEMO_ADMIN_PASSWORD") or None,
            demo_owner_password=os.getenv("TRUSTVAULT_DEMO_OWNER_PASSWORD") or None,
            demo_viewer_password=os.getenv("TRUSTVAULT_DEMO_VIEWER_PASSWORD") or None,
        )
