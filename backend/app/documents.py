import asyncio
import io
import logging
import secrets
import tempfile
import zipfile
from collections.abc import AsyncGenerator, Generator
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree
from urllib.parse import quote
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.auth import get_current_user, require_csrf
from app.audit import record_audit
from app.database import get_db
from app.models import Document, DocumentPermission, StorageOperation, User
from app.schemas import (
    DocumentMetadataUpdate,
    DocumentRead,
    PermissionGrant,
    PermissionRead,
    PermissionUpdate,
    SharedDocumentRead,
)
from app.storage import (
    DocumentStorage,
    StorageError,
    StorageObjectNotFoundError,
    StorageProviderUnavailableError,
    StorageTimeoutError,
)
from app.storage_operations import (
    StorageOperationLeaseLostError,
    activate_uploaded_document,
    create_upload_operation,
    mark_storage_operation_retryable,
    process_storage_operation,
)

router = APIRouter(prefix="/documents", tags=["documents"])
logger = logging.getLogger(__name__)


def _storage_for(request: Request, provider_name: str) -> DocumentStorage:
    try:
        return request.app.state.storage_providers.get(provider_name)
    except StorageProviderUnavailableError:
        logger.error("Document references an unavailable storage provider")
        raise HTTPException(
            status_code=503, detail="Document storage is unavailable"
        ) from None


def _storage_http_exception(error: StorageError | OSError) -> HTTPException:
    if isinstance(error, StorageObjectNotFoundError):
        return HTTPException(status_code=404, detail="Document not found")
    if isinstance(error, (StorageProviderUnavailableError, TimeoutError)):
        return HTTPException(
            status_code=503, detail="Document storage is temporarily unavailable"
        )
    return HTTPException(status_code=500, detail="Unable to access document")


MAX_UPLOAD_BYTES = 4 * 1024 * 1024
DOCX_SPOOL_MEMORY_BYTES = 1024 * 1024
MAX_DOCX_PREVIEW_XML_BYTES = 20 * 1024 * 1024
ALLOWED_TYPES = {
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".txt": "text/plain",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
}
def _validate_metadata_text(value: str, field: str, max_length: int) -> str:
    value = value.strip()
    if (
        not value
        or len(value) > max_length
        or any(ord(character) < 32 for character in value)
        or "/" in value
        or "\\" in value
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid document {field}",
        )
    return value


def _make_document_read(document: Document) -> DocumentRead:
    created_at = document.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return DocumentRead(
        id=document.id,
        name=document.name,
        category=document.category,
        filename=document.original_name,
        content_type=document.content_type,
        size_bytes=document.size_bytes,
        created_at=created_at,
        owner_email=document.owner.email,
    )


def _record_audit(
    db: Session,
    actor: User,
    action: str,
    document: Document,
    metadata: dict[str, object],
    target_type: str = "document",
    target_id: str | None = None,
) -> None:
    record_audit(
        db,
        actor.id,
        action,
        target_type,
        target_id or document.id,
        metadata,
    )


def _document_for_download(
    db: Session, document_id: str, user: User
) -> Document:
    document = db.scalar(
        select(Document).where(
            Document.id == document_id,
            Document.deleted_at.is_(None),
            Document.storage_state == "active",
        )
    )
    if document is None:
        _record_denied_download(db, user, document_id, "not_found")
        raise HTTPException(status_code=404, detail="Document not found")
    if document.owner_id == user.id:
        return document
    permission = db.scalar(
        select(DocumentPermission).where(
            DocumentPermission.document_id == document.id,
            DocumentPermission.user_id == user.id,
            DocumentPermission.revoked_at.is_(None),
            DocumentPermission.access_level == "read",
        )
    )
    if permission is None:
        _record_denied_download(db, user, document.id, "not_found")
        raise HTTPException(status_code=404, detail="Document not found")
    if not permission.can_download:
        _record_denied_download(db, user, document.id, "download_not_granted")
        raise HTTPException(
            status_code=403, detail="Download permission is not enabled for this document"
        )
    return document


def _record_denied_download(
    db: Session, user: User, document_id: str, reason: str
) -> None:
    try:
        record_audit(
            db,
            user.id,
            "document.download_denied",
            "document",
            document_id[:64],
            {"reason": reason},
        )
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Could not record denied document download")
        raise HTTPException(
            status_code=500, detail="Unable to authorize document download"
        ) from None


def _document_for_preview(
    db: Session, document_id: str, user: User
) -> Document:
    document = db.scalar(
        select(Document).where(
            Document.id == document_id,
            Document.deleted_at.is_(None),
            Document.storage_state == "active",
        )
    )
    if document is None:
        raise HTTPException(status_code=404, detail="Document not found")
    if document.owner_id == user.id:
        return document
    permission = db.scalar(
        select(DocumentPermission).where(
            DocumentPermission.document_id == document.id,
            DocumentPermission.user_id == user.id,
            DocumentPermission.revoked_at.is_(None),
            DocumentPermission.access_level == "read",
        )
    )
    if permission is None:
        raise HTTPException(status_code=404, detail="Document not found")
    return document


def _document_for_edit(
    db: Session, document_id: str, user: User
) -> Document:
    document = db.scalar(
        select(Document).where(
            Document.id == document_id,
            Document.deleted_at.is_(None),
            Document.storage_state == "active",
        )
    )
    if document is None:
        raise HTTPException(status_code=404, detail="Document not found")
    if document.owner_id == user.id:
        return document
    raise HTTPException(status_code=404, detail="Document not found")


def _owned_document(db: Session, document_id: str, user: User) -> Document:
    document = db.scalar(
        select(Document).where(
            Document.id == document_id,
            Document.owner_id == user.id,
            Document.deleted_at.is_(None),
            Document.storage_state == "active",
        )
    )
    if document is None:
        raise HTTPException(status_code=404, detail="Document not found")
    return document


def _permission_read(permission: DocumentPermission) -> PermissionRead:
    created_at = permission.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return PermissionRead(
        id=permission.id,
        user_id=permission.user_id,
        user_email=permission.user.email,
        access_level=permission.access_level,
        can_download=permission.can_download,
        created_at=created_at,
    )


def _validate_signature(extension: str, content: bytes) -> bool:
    if extension == ".pdf":
        return content.startswith(b"%PDF-")
    if extension == ".png":
        return content.startswith(b"\x89PNG\r\n\x1a\n")
    if extension in {".jpg", ".jpeg"}:
        return content.startswith(b"\xff\xd8\xff")
    if extension == ".txt":
        return b"\x00" not in content and _is_utf8(content)
    if extension == ".docx":
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                entries = set(archive.namelist())
                return {
                    "[Content_Types].xml",
                    "word/document.xml",
                } <= entries
        except (OSError, zipfile.BadZipFile):
            return False
    return False


def _is_utf8(content: bytes) -> bool:
    try:
        content.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def _stream_file(storage: DocumentStorage, storage_key: str) -> Generator[bytes, None, None]:
    with storage.open_read(storage_key) as stored_file:
        while chunk := stored_file.read(64 * 1024):
            yield chunk


def _bytes_stream(content: bytes) -> Generator[bytes, None, None]:
    if content:
        yield content


def _close_stream(stream: Generator[bytes, None, None]) -> None:
    try:
        stream.close()
    except (StorageError, OSError, TimeoutError) as error:
        logger.error("Document response stream close failed: %s", type(error).__name__)


def _next_chunk(stream: Generator[bytes, None, None]) -> tuple[bool, bytes]:
    try:
        return True, next(stream)
    except StopIteration:
        return False, b""


async def _async_stream(
    stream: Generator[bytes, None, None],
) -> AsyncGenerator[bytes, None]:
    try:
        while True:
            has_chunk, chunk = await asyncio.to_thread(_next_chunk, stream)
            if not has_chunk:
                return
            yield chunk
    finally:
        await asyncio.to_thread(_close_stream, stream)


def _docx_preview_text(storage: DocumentStorage, storage_key: str) -> bytes:
    try:
        with (
            storage.open_read(storage_key) as stored_file,
            tempfile.SpooledTemporaryFile(
                max_size=DOCX_SPOOL_MEMORY_BYTES, mode="w+b"
            ) as seekable_file,
        ):
            total_bytes = 0
            while chunk := stored_file.read(64 * 1024):
                total_bytes += len(chunk)
                if total_bytes > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413, detail="Document is too large to preview"
                    )
                seekable_file.write(chunk)
            seekable_file.seek(0)
            with zipfile.ZipFile(seekable_file) as archive:
                info = archive.getinfo("word/document.xml")
                if info.file_size > MAX_DOCX_PREVIEW_XML_BYTES:
                    raise HTTPException(
                        status_code=413, detail="Document is too large to preview"
                    )
                xml_content = archive.read(info)
        if b"<!DOCTYPE" in xml_content.upper() or b"<!ENTITY" in xml_content.upper():
            raise HTTPException(status_code=415, detail="Document preview is unavailable")
        root = ElementTree.fromstring(xml_content)
    except StorageObjectNotFoundError:
        raise HTTPException(status_code=404, detail="Document not found") from None
    except StorageError as error:
        logger.error("DOCX storage read failed: %s", type(error).__name__)
        raise _storage_http_exception(error) from None
    except TimeoutError as error:
        logger.error("DOCX storage read timed out")
        raise _storage_http_exception(error) from None
    except OSError as error:
        logger.error("DOCX storage read failed")
        raise _storage_http_exception(error) from None
    except HTTPException:
        raise
    except (OSError, KeyError, zipfile.BadZipFile, ElementTree.ParseError):
        logger.exception("Could not read DOCX preview")
        raise HTTPException(
            status_code=415, detail="Document preview is unavailable"
        ) from None

    word_namespace = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
    paragraphs = [
        "".join(node.text or "" for node in paragraph.iter(f"{word_namespace}t"))
        for paragraph in root.iter(f"{word_namespace}p")
    ]
    return "\n".join(paragraphs).encode("utf-8")


@router.post(
    "",
    response_model=DocumentRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_csrf)],
)
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    name: str | None = Form(default=None, max_length=160),
    category: str = Form(default="Uncategorized", max_length=80),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DocumentRead:
    filename = file.filename or ""
    if (
        not filename
        or "/" in filename
        or "\\" in filename
        or any(ord(character) < 32 for character in filename)
        or len(filename) > 255
    ):
        raise HTTPException(status_code=400, detail="Invalid document filename")

    extension = Path(filename).suffix.lower()
    expected_type = ALLOWED_TYPES.get(extension)
    if expected_type is None or file.content_type != expected_type:
        raise HTTPException(status_code=415, detail="Unsupported document type")

    display_name = _validate_metadata_text(
        name if name is not None else filename, "name", 160
    )
    category = _validate_metadata_text(category, "category", 80)

    content = bytearray()
    while chunk := await file.read(64 * 1024):
        content.extend(chunk)
        if len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Document exceeds 4 MB limit")
    data = bytes(content)
    if not _validate_signature(extension, data):
        raise HTTPException(status_code=415, detail="Document content is invalid")

    document = Document(
        id=str(uuid4()),
        owner_id=user.id,
        name=display_name,
        category=category,
        original_name=filename,
        storage_key=secrets.token_hex(16),
        storage_provider=request.app.state.default_storage_provider,
        content_type=expected_type,
        size_bytes=len(data),
    )
    storage = _storage_for(request, document.storage_provider)
    operation, lease_token = create_upload_operation(db, document, user.id)
    try:
        db.flush()
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Could not create document upload operation")
        raise HTTPException(
            status_code=500, detail="Unable to store document"
        ) from None

    try:
        await asyncio.to_thread(storage.write, document.storage_key, data)
    except (StorageError, OSError) as error:
        db.rollback()
        category = (
            "timeout"
            if isinstance(error, (TimeoutError, StorageTimeoutError))
            else (
                "provider_unavailable"
                if isinstance(error, StorageProviderUnavailableError)
                else "storage_error"
            )
        )
        mark_storage_operation_retryable(
            request.app.state.session_factory,
            operation.id,
            lease_token,
            category,
        )
        logger.error("Document upload failed (%s)", category)
        if isinstance(error, (StorageProviderUnavailableError, TimeoutError)):
            raise HTTPException(
                status_code=503,
                detail="Document storage is temporarily unavailable",
            ) from None
        raise HTTPException(
            status_code=500, detail="Unable to store document"
        ) from None

    try:
        activate_uploaded_document(
            db,
            operation.id,
            lease_token,
            document,
            user.id,
            {"category": category, "name": display_name, "size_bytes": len(data)},
        )
        db.commit()
        db.refresh(document)
    except (
        StorageError,
        StorageOperationLeaseLostError,
        OSError,
        SQLAlchemyError,
    ) as error:
        db.rollback()
        logger.error("Could not finalize document upload (%s)", type(error).__name__)
        if isinstance(error, (StorageProviderUnavailableError, TimeoutError)):
            raise HTTPException(
                status_code=503,
                detail="Document storage is temporarily unavailable",
            ) from None
        raise HTTPException(
            status_code=500, detail="Unable to store document"
        ) from None
    return _make_document_read(document)


@router.get("", response_model=list[DocumentRead])
def list_documents(
    search: str | None = Query(default=None, max_length=160),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[DocumentRead]:
    statement = (
        select(Document)
        .where(
            Document.owner_id == user.id,
            Document.deleted_at.is_(None),
            Document.storage_state == "active",
        )
        .order_by(Document.created_at.desc(), Document.id)
    )
    if search and search.strip():
        term = search.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        statement = statement.where(Document.name.ilike(f"%{term}%", escape="\\"))
    return [_make_document_read(document) for document in db.scalars(statement)]


@router.get("/shared", response_model=list[SharedDocumentRead])
def list_shared_documents(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[SharedDocumentRead]:
    statement = (
        select(Document, DocumentPermission)
        .join(DocumentPermission, DocumentPermission.document_id == Document.id)
        .where(
            DocumentPermission.user_id == user.id,
            DocumentPermission.revoked_at.is_(None),
            DocumentPermission.access_level == "read",
            Document.deleted_at.is_(None),
            Document.storage_state == "active",
        )
        .order_by(Document.created_at.desc(), Document.id)
    )
    return [
        SharedDocumentRead(
            **_make_document_read(document).model_dump(),
            access_level=permission.access_level,
            can_download=permission.can_download,
        )
        for document, permission in db.execute(statement)
    ]


@router.get(
    "/{document_id}/permissions", response_model=list[PermissionRead]
)
def list_document_permissions(
    document_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[PermissionRead]:
    document = _owned_document(db, document_id, user)
    permissions = db.scalars(
        select(DocumentPermission)
        .where(
            DocumentPermission.document_id == document.id,
            DocumentPermission.revoked_at.is_(None),
        )
        .order_by(DocumentPermission.created_at, DocumentPermission.id)
    )
    return [_permission_read(permission) for permission in permissions]


@router.post(
    "/{document_id}/permissions",
    response_model=PermissionRead,
    dependencies=[Depends(require_csrf)],
)
def grant_document_permission(
    document_id: str,
    grant: PermissionGrant,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PermissionRead:
    document = _owned_document(db, document_id, user)
    recipient = db.scalar(
        select(User).where(
            User.email == grant.email,
            User.disabled_at.is_(None),
        )
    )
    if recipient is None:
        raise HTTPException(status_code=404, detail="User not found")
    if recipient.id == user.id:
        raise HTTPException(
            status_code=422, detail="Cannot share a document with its owner"
        )

    permission = db.scalar(
        select(DocumentPermission).where(
            DocumentPermission.document_id == document.id,
            DocumentPermission.user_id == recipient.id,
        )
    )
    previous_level = permission.access_level if permission else None
    previous_can_download = permission.can_download if permission else False
    was_revoked = permission is not None and permission.revoked_at is not None
    if permission is None:
        permission = DocumentPermission(
            id=str(uuid4()),
            document_id=document.id,
            user_id=recipient.id,
            access_level=grant.access_level,
            can_download=grant.can_download,
            granted_by=user.id,
        )
        db.add(permission)
        action = "permission.granted"
    elif was_revoked:
        permission.access_level = grant.access_level
        permission.can_download = grant.can_download
        permission.granted_by = user.id
        permission.revoked_at = None
        permission.created_at = datetime.now(timezone.utc).replace(tzinfo=None)
        action = "permission.granted"
    elif (
        previous_level != grant.access_level
        or permission.can_download != grant.can_download
    ):
        permission.access_level = grant.access_level
        permission.can_download = grant.can_download
        permission.granted_by = user.id
        action = "permission.updated"
    else:
        return _permission_read(permission)

    _record_audit(
        db,
        user,
        action,
        document,
        {
            "access_level": grant.access_level,
            "document_id": document.id,
            "previous_access_level": previous_level,
            "can_download": permission.can_download,
            "previous_can_download": previous_can_download,
            "recipient_id": recipient.id,
        },
        target_type="document_permission",
        target_id=permission.id,
    )
    try:
        db.commit()
        db.refresh(permission)
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Could not update document permissions")
        raise HTTPException(
            status_code=500, detail="Unable to update document permissions"
        ) from None
    return _permission_read(permission)


@router.patch(
    "/{document_id}/permissions/{permission_id}",
    response_model=PermissionRead,
    dependencies=[Depends(require_csrf)],
)
def update_document_permission(
    document_id: str,
    permission_id: str,
    updates: PermissionUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PermissionRead:
    document = _owned_document(db, document_id, user)
    permission = db.scalar(
        select(DocumentPermission).where(
            DocumentPermission.id == permission_id,
            DocumentPermission.document_id == document.id,
            DocumentPermission.revoked_at.is_(None),
            DocumentPermission.access_level == "read",
        )
    )
    if permission is None:
        raise HTTPException(status_code=404, detail="Permission not found")
    if permission.can_download == updates.can_download:
        return _permission_read(permission)

    previous_can_download = permission.can_download
    permission.can_download = updates.can_download
    _record_audit(
        db,
        user,
        "permission.download_updated",
        document,
        {
            "can_download": updates.can_download,
            "document_id": document.id,
            "previous_can_download": previous_can_download,
            "recipient_id": permission.user_id,
        },
        target_type="document_permission",
        target_id=permission.id,
    )
    try:
        db.commit()
        db.refresh(permission)
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Could not update download permission")
        raise HTTPException(
            status_code=500, detail="Unable to update download permission"
        ) from None
    return _permission_read(permission)


@router.delete(
    "/{document_id}/permissions/{permission_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_csrf)],
)
def revoke_document_permission(
    document_id: str,
    permission_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    document = _owned_document(db, document_id, user)
    permission = db.scalar(
        select(DocumentPermission).where(
            DocumentPermission.id == permission_id,
            DocumentPermission.document_id == document.id,
            DocumentPermission.revoked_at.is_(None),
        )
    )
    if permission is None:
        raise HTTPException(status_code=404, detail="Permission not found")

    _record_audit(
        db,
        user,
        "permission.revoked",
        document,
        {
            "access_level": permission.access_level,
            "can_download": permission.can_download,
            "document_id": document.id,
            "recipient_id": permission.user_id,
        },
        target_type="document_permission",
        target_id=permission.id,
    )
    permission.revoked_at = datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Could not revoke document permissions")
        raise HTTPException(
            status_code=500, detail="Unable to revoke document permissions"
        ) from None


@router.get("/{document_id}/download")
def download_document(
    document_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    document = _document_for_download(db, document_id, user)
    return _stream_document(
        request, db, user, document, "document.downloaded", "attachment"
    )


@router.get("/{document_id}/preview")
def preview_document(
    document_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    document = _document_for_preview(db, document_id, user)
    if document.content_type not in ALLOWED_TYPES.values():
        raise HTTPException(status_code=415, detail="Document preview is unavailable")
    if document.content_type == ALLOWED_TYPES[".docx"]:
        preview_text = _docx_preview_text(
            _storage_for(request, document.storage_provider), document.storage_key
        )
        return _stream_document(
            request,
            db,
            user,
            document,
            "document.previewed",
            "inline",
            content_type="text/plain; charset=utf-8",
            content_override=preview_text,
        )
    return _stream_document(
        request, db, user, document, "document.previewed", "inline"
    )


def _stream_document(
    request: Request,
    db: Session,
    user: User,
    document: Document,
    action: str,
    disposition: str,
    content_type: str | None = None,
    content_override: bytes | None = None,
) -> StreamingResponse:
    storage = _storage_for(request, document.storage_provider)
    try:
        exists = storage.exists(document.storage_key)
    except StorageError as error:
        logger.error("Document storage check failed: %s", type(error).__name__)
        raise _storage_http_exception(error) from None
    except TimeoutError as error:
        logger.error("Document storage check timed out")
        raise _storage_http_exception(error) from None
    except OSError as error:
        logger.error("Document storage check failed")
        raise _storage_http_exception(error) from None
    if not exists:
        raise HTTPException(status_code=404, detail="Document not found")
    stream = (
        _bytes_stream(content_override)
        if content_override is not None
        else _stream_file(storage, document.storage_key)
    )
    try:
        first_chunk = next(stream, b"")
        _record_audit(
            db,
            user,
            action,
            document,
            {"size_bytes": document.size_bytes},
        )
        db.commit()
    except StorageError as error:
        _close_stream(stream)
        logger.error("Document stream initialization failed: %s", type(error).__name__)
        raise _storage_http_exception(error) from None
    except TimeoutError as error:
        _close_stream(stream)
        logger.error("Document stream initialization timed out")
        raise _storage_http_exception(error) from None
    except OSError as error:
        _close_stream(stream)
        logger.error("Document stream initialization failed")
        raise _storage_http_exception(error) from None
    except SQLAlchemyError:
        db.rollback()
        _close_stream(stream)
        logger.exception("Could not record document download")
        raise HTTPException(
            status_code=500, detail="Unable to download document"
        ) from None

    def content() -> Generator[bytes, None, None]:
        try:
            if first_chunk:
                yield first_chunk
            yield from stream
        except (StorageError, OSError, TimeoutError) as error:
            logger.error("Document response stream failed: %s", type(error).__name__)
            raise
        finally:
            _close_stream(stream)

    return StreamingResponse(
        _async_stream(content()),
        media_type=content_type or document.content_type,
        headers={
            "Content-Disposition": (
                f"{disposition}; filename*=UTF-8''{quote(document.original_name)}"
            ),
            "Cache-Control": (
                "no-store" if disposition == "inline" else "private, no-store"
            ),
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.patch(
    "/{document_id}",
    response_model=DocumentRead,
    dependencies=[Depends(require_csrf)],
)
def update_document(
    document_id: str,
    updates: DocumentMetadataUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DocumentRead:
    document = _document_for_edit(db, document_id, user)
    old_values: dict[str, str] = {}
    new_values: dict[str, str] = {}
    for field in ("name", "category"):
        value = getattr(updates, field)
        if value is not None:
            old_values[field] = getattr(document, field)
            new_values[field] = value
            setattr(document, field, value)
    try:
        _record_audit(
            db,
            user,
            "document.updated",
            document,
            {"new": new_values, "previous": old_values},
        )
        db.commit()
        db.refresh(document)
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Could not update document metadata")
        raise HTTPException(
            status_code=500, detail="Unable to update document"
        ) from None
    return _make_document_read(document)


@router.delete(
    "/{document_id}", status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_csrf)],
)
def delete_document(
    document_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    document = db.scalar(
        select(Document).where(
            Document.id == document_id,
            Document.owner_id == user.id,
            Document.deleted_at.is_(None),
            Document.storage_state == "active",
        )
    )
    if document is None:
        raise HTTPException(status_code=404, detail="Document not found")

    operation = StorageOperation(
        id=str(uuid4()),
        document_id=document.id,
        provider=document.storage_provider,
        storage_key=document.storage_key,
        operation_type="delete",
        status="pending",
        attempt_count=0,
        actor_id=user.id,
    )
    document.deleted_at = datetime.now(timezone.utc).replace(tzinfo=None)
    document.storage_state = "deleting"
    db.add(operation)
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Could not create document deletion operation")
        raise HTTPException(
            status_code=500, detail="Unable to delete document"
        ) from None

    if not process_storage_operation(
        request.app.state.session_factory,
        request.app.state.storage_providers,
        operation.id,
    ):
        raise HTTPException(
            status_code=503,
            detail="Document deletion is pending storage cleanup",
        )
