import io
import os
import re
import secrets
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import BinaryIO, ContextManager, Protocol, runtime_checkable

import httpx2
from vercel import blob as vercel_blob
from vercel.blob import sync as vercel_blob_sync


_STORAGE_KEY_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_QUARANTINE_KEY_PATTERN = re.compile(
    r"^[0-9a-f]{32}\.[0-9a-f]{16}\.deleting$"
)
_VERCEL_BLOB_PREFIX = "trustvault/documents/"


class StorageError(Exception):
    pass


class StorageObjectNotFoundError(StorageError):
    pass


class StorageProviderUnavailableError(StorageError):
    pass


class StorageTimeoutError(StorageProviderUnavailableError):
    pass


class StorageOperationError(StorageError):
    pass


class InvalidStorageKeyError(StorageObjectNotFoundError):
    pass


@runtime_checkable
class DocumentStorage(Protocol):
    def write(self, storage_key: str, content: bytes) -> None: ...

    def open_read(self, storage_key: str) -> BinaryIO:
        """Return a readable stream owned by the caller, which must close it."""
        ...

    def exists(self, storage_key: str) -> bool: ...

    def delete(self, storage_key: str) -> None:
        """Delete an object idempotently; deleting an absent object succeeds."""
        ...


@runtime_checkable
class RecoverableFilesystemDeletion(Protocol):
    def quarantine(self, storage_key: str) -> str | None: ...

    def restore(self, storage_key: str, quarantine_key: str) -> None: ...

    def delete_quarantined(self, quarantine_key: str) -> None: ...


class StorageProviderRegistry:
    def __init__(self, providers: dict[str, DocumentStorage]) -> None:
        self._providers = dict(providers)

    def get(self, provider_name: str) -> DocumentStorage:
        provider = self._providers.get(provider_name)
        if provider is None:
            raise StorageProviderUnavailableError(
                f"Storage provider is unavailable: {provider_name}"
            )
        return provider


def _vercel_blob_error(error: Exception, message: str) -> StorageError:
    if isinstance(error, vercel_blob.BlobNotFoundError):
        return StorageObjectNotFoundError("Document object not found")
    if isinstance(error, (httpx2.TimeoutException, TimeoutError)):
        return StorageTimeoutError(message)
    if isinstance(
        error,
        (
            vercel_blob.BlobAccessError,
            vercel_blob.BlobCredentialsError,
            vercel_blob.BlobServiceNotAvailable,
            vercel_blob.BlobServiceRateLimited,
            vercel_blob.BlobStoreNotFoundError,
            vercel_blob.BlobStoreSuspendedError,
        ),
    ):
        return StorageProviderUnavailableError(message)
    return StorageOperationError(message)


class _VercelBlobReadStream(io.RawIOBase):
    def __init__(
        self,
        context_manager: ContextManager[Iterable[bytes]],
        download: Iterable[bytes],
    ) -> None:
        self._context_manager = context_manager
        self._chunks: Iterator[bytes] = iter(download)
        self._buffer = bytearray()

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: memoryview) -> int:
        if self.closed:
            return 0
        while not self._buffer:
            try:
                self._buffer.extend(next(self._chunks))
            except StopIteration:
                return 0
            except Exception as error:
                self._exit_context(error)
                raise _vercel_blob_error(error, "Could not read document") from None

        bytes_read = min(len(buffer), len(self._buffer))
        buffer[:bytes_read] = self._buffer[:bytes_read]
        del self._buffer[:bytes_read]
        return bytes_read

    def close(self) -> None:
        if self.closed:
            return
        self._exit_context()
        super().close()

    def _exit_context(self, error: Exception | None = None) -> None:
        try:
            if error is None:
                self._context_manager.__exit__(None, None, None)
            else:
                self._context_manager.__exit__(
                    type(error), error, error.__traceback__
                )
        except Exception as close_error:
            if error is None:
                raise _vercel_blob_error(
                    close_error, "Could not close document stream"
                ) from None
        finally:
            super().close()


class VercelBlobStorage:
    def _pathname(self, storage_key: str) -> str:
        if not _STORAGE_KEY_PATTERN.fullmatch(storage_key):
            raise InvalidStorageKeyError("Invalid storage key")
        return f"{_VERCEL_BLOB_PREFIX}{storage_key}"

    def write(self, storage_key: str, content: bytes) -> None:
        try:
            vercel_blob_sync.put_blob(
                self._pathname(storage_key),
                content,
                access="private",
                add_random_suffix=False,
                allow_overwrite=False,
            )
        except (vercel_blob.BlobError, httpx2.RequestError, OSError) as error:
            raise _vercel_blob_error(error, "Could not write document") from None

    def open_read(self, storage_key: str) -> BinaryIO:
        pathname = self._pathname(storage_key)
        entered = False
        try:
            context_manager = vercel_blob_sync.stream_blob(pathname, access="private")
            download = context_manager.__enter__()
            entered = True
            return io.BufferedReader(
                _VercelBlobReadStream(context_manager, download)
            )
        except Exception as error:
            if entered:
                context_manager.__exit__(type(error), error, error.__traceback__)
            if not isinstance(
                error,
                (vercel_blob.BlobError, httpx2.RequestError, OSError),
            ):
                raise StorageOperationError("Could not open document") from None
            raise _vercel_blob_error(error, "Could not open document") from None

    def exists(self, storage_key: str) -> bool:
        try:
            vercel_blob_sync.head_blob(self._pathname(storage_key))
            return True
        except vercel_blob.BlobNotFoundError:
            return False
        except (vercel_blob.BlobError, httpx2.RequestError, OSError) as error:
            raise _vercel_blob_error(error, "Could not inspect document") from None

    def delete(self, storage_key: str) -> None:
        try:
            vercel_blob_sync.delete_blob(self._pathname(storage_key))
        except (vercel_blob.BlobError, httpx2.RequestError, OSError) as error:
            raise _vercel_blob_error(error, "Could not delete document") from None


class FilesystemStorage:
    def __init__(self, root: Path) -> None:
        self._root = root.resolve()

    def _path(self, storage_key: str, *, quarantine: bool = False) -> Path:
        pattern = _QUARANTINE_KEY_PATTERN if quarantine else _STORAGE_KEY_PATTERN
        if not pattern.fullmatch(storage_key):
            raise InvalidStorageKeyError("Invalid storage key")
        path = (self._root / storage_key).resolve()
        if path.parent != self._root:
            raise InvalidStorageKeyError("Invalid storage key")
        return path

    def write(self, storage_key: str, content: bytes) -> None:
        path = self._path(storage_key)
        try:
            with path.open("xb") as stored_file:
                stored_file.write(content)
            if os.name == "posix":
                path.chmod(0o600)
        except OSError as error:
            raise StorageOperationError("Could not write document") from error

    def open_read(self, storage_key: str) -> BinaryIO:
        path = self._path(storage_key)
        try:
            return path.open("rb")
        except FileNotFoundError as error:
            raise StorageObjectNotFoundError("Document object not found") from error
        except OSError as error:
            raise StorageOperationError("Could not open document") from error

    def exists(self, storage_key: str) -> bool:
        path = self._path(storage_key)
        try:
            return path.is_file()
        except OSError as error:
            raise StorageOperationError("Could not inspect document") from error

    def delete(self, storage_key: str) -> None:
        path = self._path(storage_key)
        try:
            path.unlink(missing_ok=True)
        except OSError as error:
            raise StorageOperationError("Could not delete document") from error

    def quarantine(self, storage_key: str) -> str | None:
        source = self._path(storage_key)
        try:
            if not source.exists():
                return None
            quarantine_key = f"{storage_key}.{secrets.token_hex(8)}.deleting"
            source.replace(self._path(quarantine_key, quarantine=True))
            return quarantine_key
        except OSError as error:
            raise StorageOperationError("Could not quarantine document") from error

    def restore(self, storage_key: str, quarantine_key: str) -> None:
        source = self._path(quarantine_key, quarantine=True)
        target = self._path(storage_key)
        try:
            if not source.exists():
                if target.exists():
                    return
                raise StorageObjectNotFoundError("Quarantined object not found")
            if target.exists():
                raise StorageOperationError("Document restoration target already exists")
            source.replace(target)
        except StorageError:
            raise
        except OSError as error:
            raise StorageOperationError("Could not restore document") from error

    def delete_quarantined(self, quarantine_key: str) -> None:
        path = self._path(quarantine_key, quarantine=True)
        try:
            path.unlink(missing_ok=True)
        except OSError as error:
            raise StorageOperationError("Could not clean up quarantined document") from error
