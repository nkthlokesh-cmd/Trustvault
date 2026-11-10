from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator


class Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    display_name: str | None = Field(default=None, max_length=120)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        return str(value).strip().casefold()

    @field_validator("display_name", mode="before")
    @classmethod
    def normalize_display_name(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip() or None
        return value


class UserRead(BaseModel):
    id: UUID
    email: EmailStr
    display_name: str
    is_admin: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class CsrfToken(BaseModel):
    csrf_token: str


class DocumentRead(BaseModel):
    id: UUID
    name: str
    category: str
    filename: str
    content_type: str
    size_bytes: int
    created_at: datetime
    owner_email: EmailStr


class DocumentMetadataUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str | None = Field(default=None, min_length=1, max_length=160)
    category: str | None = Field(default=None, min_length=1, max_length=80)

    @field_validator("name", "category")
    @classmethod
    def validate_metadata_text(cls, value: str | None) -> str | None:
        if value is not None and (
            any(ord(character) < 32 for character in value)
            or "/" in value
            or "\\" in value
        ):
            raise ValueError("Metadata contains invalid characters")
        return value

    @model_validator(mode="after")
    def require_a_change(self) -> "DocumentMetadataUpdate":
        if self.name is None and self.category is None:
            raise ValueError("At least one metadata field is required")
        return self


class PermissionGrant(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    email: EmailStr
    access_level: Literal["read"]
    can_download: bool = False

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        return str(value).strip().casefold()


class PermissionUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    can_download: bool


class PermissionRead(BaseModel):
    id: UUID
    user_id: UUID
    user_email: EmailStr
    access_level: Literal["read", "edit"]
    can_download: bool
    created_at: datetime


class SharedDocumentRead(DocumentRead):
    access_level: Literal["read"]
    can_download: bool


class AdminUserRead(BaseModel):
    id: UUID
    email: EmailStr
    is_admin: bool
    is_active: bool
    created_at: datetime
    disabled_at: datetime | None


class AdminUserStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_active: bool


class AdminUserPage(BaseModel):
    items: list[AdminUserRead]
    total: int
    limit: int
    offset: int


class AdminDocumentRead(BaseModel):
    id: UUID
    filename: str
    owner_id: UUID
    owner_email: EmailStr
    size_bytes: int
    content_type: str
    created_at: datetime
    updated_at: datetime


class AdminDocumentPage(BaseModel):
    items: list[AdminDocumentRead]
    total: int
    limit: int
    offset: int


class AdminPermissionRead(BaseModel):
    id: UUID
    document_id: UUID
    filename: str
    owner_id: UUID
    owner_email: EmailStr
    user_id: UUID
    user_email: EmailStr
    access_level: str
    granted_at: datetime
    revoked_at: datetime | None
    status: Literal["active", "revoked", "legacy_inactive"]


class AdminPermissionPage(BaseModel):
    items: list[AdminPermissionRead]
    total: int
    limit: int
    offset: int


class AdminAuditEventRead(BaseModel):
    id: int
    actor_id: UUID | None
    actor_display_name: str | None
    actor_email: str | None
    actor_role: str | None
    document_id: str | None
    document_name: str | None
    permission_id: str | None
    permission_owner: str | None
    permission_viewer: str | None
    download_allowed: bool | None
    permission_status: Literal["active", "revoked"] | None
    target_display: str | None
    action_details: str | None
    action: str
    target_type: str
    target_id: str
    created_at: datetime
    metadata_json: str
    previous_hash: str
    event_hash: str


class AdminAuditEventPage(BaseModel):
    items: list[AdminAuditEventRead]
    total: int
    limit: int
    offset: int


class AdminAuditIntegrityRead(BaseModel):
    is_valid: bool
    event_count: int
    first_invalid_event_id: int | None
    failure_reason: Literal["event_order", "broken_link", "event_hash"] | None
