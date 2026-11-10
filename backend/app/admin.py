import json
import logging
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, aliased

from app.audit import record_audit, verify_audit_chain
from app.auth import get_current_user, require_csrf
from app.database import get_db
from app.models import (
    AuditEvent,
    AuthSession,
    Document,
    DocumentPermission,
    User,
)
from app.schemas import (
    AdminAuditEventPage,
    AdminAuditEventRead,
    AdminAuditIntegrityRead,
    AdminDocumentPage,
    AdminDocumentRead,
    AdminPermissionPage,
    AdminPermissionRead,
    AdminUserPage,
    AdminUserRead,
    AdminUserStatusUpdate,
)

router = APIRouter(prefix="/admin", tags=["administration"])
logger = logging.getLogger(__name__)


def require_admin(user: User = Depends(get_current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator access required",
        )
    return user


def _page_bounds(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> tuple[int, int]:
    return limit, offset


def _audit_metadata(event: AuditEvent) -> dict[str, object]:
    try:
        metadata = json.loads(event.metadata_json)
    except json.JSONDecodeError:
        logger.warning("Audit event %s contains invalid metadata JSON", event.id)
        return {}
    return metadata if isinstance(metadata, dict) else {}


def _user_label(user: User | None, user_id: str | None) -> str:
    if user is None:
        return "Deleted User" if user_id else "Unavailable"
    if user.display_name and user.display_name != user.email:
        return f"{user.display_name} ({user.email})"
    return user.email


def _audit_action_details(
    event: AuditEvent, metadata: dict[str, object]
) -> str | None:
    if event.action == "document.uploaded":
        category = metadata.get("category")
        return f"Category: {category}" if isinstance(category, str) else None
    if event.action == "document.updated":
        previous = metadata.get("previous")
        new = metadata.get("new")
        if isinstance(previous, dict) and isinstance(new, dict):
            changes = [
                f"{field.title()}: {previous[field]} → {new[field]}"
                for field in ("name", "category")
                if isinstance(previous.get(field), str)
                and isinstance(new.get(field), str)
            ]
            return "; ".join(changes) or None
    if event.action == "document.deleted":
        name = metadata.get("name")
        return f"Document label at deletion: {name}" if isinstance(name, str) else None
    if event.action == "document.download_denied":
        reason = metadata.get("reason")
        if reason == "download_not_granted":
            return "Download denied: permission not granted"
        if reason == "not_found":
            return "Download denied: document unavailable or not shared"
    if event.action in {"admin.user.activated", "admin.user.deactivated"}:
        return (
            "Account activated"
            if metadata.get("is_active") is True
            else "Account deactivated"
        )
    size_bytes = metadata.get("size_bytes")
    if event.action in {"document.downloaded", "document.previewed"} and isinstance(
        size_bytes, int
    ):
        return f"Size: {size_bytes} bytes"
    return None


@router.get("/users", response_model=AdminUserPage)
def list_users(
    page: tuple[int, int] = Depends(_page_bounds),
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminUserPage:
    limit, offset = page
    total = db.scalar(select(func.count()).select_from(User)) or 0
    users = db.scalars(
        select(User).order_by(User.created_at.desc(), User.id).limit(limit).offset(offset)
    )
    return AdminUserPage(
        items=[
            AdminUserRead(
                id=user.id,
                email=user.email,
                is_admin=user.is_admin,
                is_active=user.disabled_at is None,
                created_at=user.created_at,
                disabled_at=user.disabled_at,
            )
            for user in users
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/users/{user_id}", response_model=AdminUserRead)
def get_user(
    user_id: UUID,
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminUserRead:
    user = db.get(User, str(user_id))
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return AdminUserRead(
        id=user.id,
        email=user.email,
        is_admin=user.is_admin,
        is_active=user.disabled_at is None,
        created_at=user.created_at,
        disabled_at=user.disabled_at,
    )


@router.patch(
    "/users/{user_id}/status",
    response_model=AdminUserRead,
    dependencies=[Depends(require_csrf)],
)
def update_user_status(
    user_id: UUID,
    update_data: AdminUserStatusUpdate,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminUserRead:
    user = db.get(User, str(user_id))
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    desired_disabled_at = None if update_data.is_active else datetime.now(timezone.utc)
    if (user.disabled_at is None) == update_data.is_active:
        return AdminUserRead(
            id=user.id,
            email=user.email,
            is_admin=user.is_admin,
            is_active=user.disabled_at is None,
            created_at=user.created_at,
            disabled_at=user.disabled_at,
        )

    try:
        if not update_data.is_active and user.is_admin:
            if db.get_bind().dialect.name == "sqlite":
                db.rollback()
                db.connection().exec_driver_sql("BEGIN IMMEDIATE")

            active_admin_ids = list(
                db.scalars(
                    select(User.id)
                    .where(User.is_admin.is_(True), User.disabled_at.is_(None))
                    .order_by(User.id)
                    .with_for_update()
                )
            )
            db.refresh(user)
            if user.disabled_at is not None:
                return AdminUserRead(
                    id=user.id,
                    email=user.email,
                    is_admin=user.is_admin,
                    is_active=False,
                    created_at=user.created_at,
                    disabled_at=user.disabled_at,
                )

            another_active_admin = (
                select(User.id)
                .where(
                    User.is_admin.is_(True),
                    User.disabled_at.is_(None),
                    User.id != user.id,
                )
                .exists()
            )
            if user.id not in active_admin_ids or len(active_admin_ids) <= 1:
                db.rollback()
                raise HTTPException(
                    status_code=409,
                    detail="Cannot deactivate the last active administrator",
                )

            changed = db.execute(
                update(User)
                .where(
                    User.id == user.id,
                    User.disabled_at.is_(None),
                    another_active_admin,
                )
                .values(disabled_at=desired_disabled_at)
            ).rowcount
            if changed != 1:
                db.rollback()
                raise HTTPException(
                    status_code=409,
                    detail="Cannot deactivate the last active administrator",
                )
        else:
            user.disabled_at = desired_disabled_at

        if not update_data.is_active:
            db.execute(
                update(AuthSession)
                .where(
                    AuthSession.user_id == user.id,
                    AuthSession.revoked_at.is_(None),
                )
                .values(revoked_at=desired_disabled_at)
            )

        action = (
            "admin.user.activated"
            if update_data.is_active
            else "admin.user.deactivated"
        )
        record_audit(
            db,
            admin.id,
            action,
            "user",
            user.id,
            {"is_active": update_data.is_active},
        )
        db.commit()
        db.expire(user)
        db.refresh(user)
    except HTTPException:
        raise
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Could not update account status")
        raise HTTPException(
            status_code=500, detail="Unable to update account status"
        ) from None

    return AdminUserRead(
        id=user.id,
        email=user.email,
        is_admin=user.is_admin,
        is_active=user.disabled_at is None,
        created_at=user.created_at,
        disabled_at=user.disabled_at,
    )


@router.get("/documents", response_model=AdminDocumentPage)
def list_document_metadata(
    page: tuple[int, int] = Depends(_page_bounds),
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminDocumentPage:
    limit, offset = page
    filters = (
        Document.deleted_at.is_(None),
        Document.storage_state == "active",
    )
    total = db.scalar(
        select(func.count()).select_from(Document).where(*filters)
    ) or 0
    documents = db.scalars(
        select(Document)
        .where(*filters)
        .order_by(Document.created_at.desc(), Document.id)
        .limit(limit)
        .offset(offset)
    )
    return AdminDocumentPage(
        items=[
            AdminDocumentRead(
                id=document.id,
                filename=document.original_name,
                owner_id=document.owner_id,
                owner_email=document.owner.email,
                size_bytes=document.size_bytes,
                content_type=document.content_type,
                created_at=document.created_at,
                updated_at=document.updated_at,
            )
            for document in documents
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/permissions", response_model=AdminPermissionPage)
def list_permissions(
    page: tuple[int, int] = Depends(_page_bounds),
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminPermissionPage:
    limit, offset = page
    owner = aliased(User)
    recipient = aliased(User)
    statement = (
        select(DocumentPermission, Document, owner, recipient)
        .join(Document, Document.id == DocumentPermission.document_id)
        .join(owner, owner.id == Document.owner_id)
        .join(recipient, recipient.id == DocumentPermission.user_id)
        .where(
            Document.deleted_at.is_(None),
            Document.storage_state == "active",
        )
    )
    total = db.scalar(
        select(func.count())
        .select_from(DocumentPermission)
        .join(Document, Document.id == DocumentPermission.document_id)
        .where(
            Document.deleted_at.is_(None),
            Document.storage_state == "active",
        )
    ) or 0
    rows = db.execute(
        statement.order_by(DocumentPermission.created_at.desc(), DocumentPermission.id)
        .limit(limit)
        .offset(offset)
    )
    return AdminPermissionPage(
        items=[
            AdminPermissionRead(
                id=permission.id,
                document_id=document.id,
                filename=document.original_name,
                owner_id=owner_user.id,
                owner_email=owner_user.email,
                user_id=recipient_user.id,
                user_email=recipient_user.email,
                access_level=permission.access_level,
                granted_at=permission.created_at,
                revoked_at=permission.revoked_at,
                status=(
                    "revoked"
                    if permission.revoked_at is not None
                    else (
                        "legacy_inactive"
                        if permission.access_level != "read"
                        else "active"
                    )
                ),
            )
            for permission, document, owner_user, recipient_user in rows
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/audit", response_model=AdminAuditEventPage)
def list_audit_events(
    event_type: str | None = Query(default=None, min_length=1, max_length=40),
    user_id: UUID | None = None,
    document_id: UUID | None = None,
    page: tuple[int, int] = Depends(_page_bounds),
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminAuditEventPage:
    limit, offset = page
    filters = []
    if event_type:
        filters.append(AuditEvent.action == event_type)
    if user_id:
        user_id_text = str(user_id)
        filters.append(
            or_(
                AuditEvent.actor_id == user_id_text,
                AuditEvent.target_id == user_id_text,
                AuditEvent.metadata_json.like(
                    f'%"recipient_id":"{user_id_text}"%'
                ),
            )
        )
    if document_id:
        document_id_text = str(document_id)
        filters.append(
            or_(
                AuditEvent.target_id == document_id_text,
                and_(
                    AuditEvent.target_type == "document_permission",
                    AuditEvent.metadata_json.like(
                        f'%"document_id":"{document_id_text}"%'
                    ),
                ),
            )
        )

    total = (
        db.scalar(select(func.count()).select_from(AuditEvent).where(*filters)) or 0
    )
    event_rows = list(
        db.scalars(
            select(AuditEvent)
            .where(*filters)
            .order_by(AuditEvent.id.desc())
            .limit(limit)
            .offset(offset)
        )
    )
    event_metadata = {event.id: _audit_metadata(event) for event in event_rows}
    document_ids = {
        event.target_id
        for event in event_rows
        if event.target_type == "document"
    }
    document_ids.update(
        metadata["document_id"]
        for metadata in event_metadata.values()
        if isinstance(metadata.get("document_id"), str)
    )
    documents = {
        document.id: document
        for document in db.scalars(
            select(Document).where(Document.id.in_(document_ids))
        )
    } if document_ids else {}
    user_ids = {
        event.actor_id
        for event in event_rows
        if event.actor_id is not None
    }
    user_ids.update(
        metadata["recipient_id"]
        for metadata in event_metadata.values()
        if isinstance(metadata.get("recipient_id"), str)
    )
    user_ids.update(
        event.target_id
        for event in event_rows
        if event.target_type == "user"
    )
    user_ids.update(
        document.owner_id for document in documents.values()
    )
    users = {
        user.id: user
        for user in db.scalars(select(User).where(User.id.in_(user_ids)))
    } if user_ids else {}

    items = []
    for event in event_rows:
        metadata = event_metadata[event.id]
        document_id = (
            event.target_id
            if event.target_type == "document"
            else metadata.get("document_id")
        )
        document = (
            documents.get(document_id)
            if isinstance(document_id, str)
            else None
        )
        document_name = (
            document.original_name
            if document is not None
            else (
                metadata.get("original_name")
                if isinstance(metadata.get("original_name"), str)
                else "Deleted Document"
            )
        )
        recipient_id = metadata.get("recipient_id")
        recipient = users.get(recipient_id) if isinstance(recipient_id, str) else None
        is_permission_event = event.target_type == "document_permission"
        permission_status = (
            "revoked"
            if event.action == "permission.revoked"
            else (
                "active"
                if event.action
                in {
                    "permission.granted",
                    "permission.updated",
                    "permission.download_updated",
                }
                else None
            )
        )
        download_allowed = metadata.get("can_download")
        if not isinstance(download_allowed, bool):
            download_allowed = None
        actor = users.get(event.actor_id) if event.actor_id else None
        target_display = document_name if document_id else None
        if is_permission_event:
            target_display = f"{document_name} · {_user_label(recipient, recipient_id)}"
        elif event.target_type == "user":
            target_user = users.get(event.target_id)
            target_display = _user_label(target_user, event.target_id)
        items.append(
            AdminAuditEventRead(
                id=event.id,
                actor_id=event.actor_id,
                actor_display_name=(
                    (actor.display_name or None) if actor else None
                ),
                actor_email=actor.email if actor else None,
                actor_role=(
                    "Admin" if actor.is_admin else "User"
                ) if actor else None,
                document_id=document_id if isinstance(document_id, str) else None,
                document_name=document_name if document_id else None,
                permission_id=event.target_id if is_permission_event else None,
                permission_owner=(
                    _user_label(actor, event.actor_id)
                    if is_permission_event
                    else None
                ),
                permission_viewer=(
                    _user_label(recipient, recipient_id)
                    if is_permission_event
                    else None
                ),
                download_allowed=download_allowed if is_permission_event else None,
                permission_status=permission_status,
                target_display=target_display,
                action_details=_audit_action_details(event, metadata),
                action=event.action,
                target_type=event.target_type,
                target_id=event.target_id,
                created_at=event.created_at,
                metadata_json=event.metadata_json,
                previous_hash=event.previous_hash,
                event_hash=event.event_hash,
            )
        )
    return AdminAuditEventPage(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/audit/integrity", response_model=AdminAuditIntegrityRead)
def get_audit_integrity(
    _admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AdminAuditIntegrityRead:
    verification = verify_audit_chain(
        db.scalars(select(AuditEvent).order_by(AuditEvent.id.asc()))
    )
    return AdminAuditIntegrityRead(
        is_valid=verification.is_valid,
        event_count=verification.event_count,
        first_invalid_event_id=verification.first_invalid_event_id,
        failure_reason=verification.failure_reason,
    )
