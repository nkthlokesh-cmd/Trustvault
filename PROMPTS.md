# TrustVault Development and Verification Record

This document summarizes the implementation that is present in the repository. Earlier drafts of this record contained PostgreSQL, Cloud SQL, and administrator-setup claims that do not match the project; those claims are not authoritative.

## Verified architecture

- **Frontend:** React 19, TypeScript, Vite, Tailwind CSS.
- **Backend:** Node.js and Express.
- **Database:** Local SQLite through Node's built-in `node:sqlite` and Drizzle ORM.
- **Authentication:** bcryptjs password hashes and SQLite-backed sessions. The browser receives a random token in an HTTP-only cookie; SQLite stores its SHA-256 hash.
- **Document storage:** Randomized filenames in a private local directory. Upload validation and SHA-256 checksums provide content checks and integrity detection; application-level encryption and malware scanning are not implemented.
- **Roles:** Admin, Owner, and Viewer, with server-side permission checks.

## Implemented workflows

- Public registration is restricted to Owner and Viewer roles; administrator accounts are created by the CLI provisioning command.
- Login, logout, session expiration, account deactivation, and cookie-only API authentication use the SQLite session table.
- Owners can upload, list, edit, delete, share, and revoke documents. READ and EDIT permissions are checked by the API on document requests.
- Administrators can manage account status and inspect document metadata and audit records, but do not receive default access to private file contents.
- Audit entries use SHA-256 hash links. Immediate SQLite transactions and an insert trigger serialize writes and require chain continuity. Update/delete triggers protect ordinary application operations.

## Verification commands

Run these commands in PowerShell when dependencies are already installed:

```powershell
npm.cmd test
npm.cmd run lint
npm.cmd run build
```

The API tests use a temporary SQLite database and cover registration, cookie sessions, role boundaries, uploads, sharing and revocation, audit verification, corrupted files, logout, origin validation, rate limiting, and concurrent audit writes. A successful build does not verify browser compatibility or interactive UI behavior; no automated browser tests are included.

## Security boundaries and limitations

- Files and SQLite data are not encrypted at rest by the application. SHA-256 checksums do not provide confidentiality.
- File signature and structure checks are not antivirus scanning or document sanitization.
- Login throttling allows five failed attempts per client IP in a 15-minute window. Its in-memory state is per process; multi-process deployments need a shared rate-limit store.
- State-changing API requests require an exact matching `Origin`. The app is designed to be same-origin and does not enable CORS.
- The audit chain is local and not externally anchored. A person with direct database access can disable triggers and rewrite or truncate the chain.
- Email verification, password reset, and multi-factor authentication are not implemented.
- The project has no automated browser/UI suite or production deployment monitoring.

## Recent hardening and corrections

- Added login throttling with generic invalid-credential responses.
- Added same-origin `Origin` checks for API state changes.
- Moved audit chain-head lookup and insert into an immediate SQLite transaction and added a chain-continuity insert trigger.
- Added tests for origin rejection, login throttling, concurrent audit writes, and invalid chain insertion.
- Corrected claims that files are encrypted, that the database uses PostgreSQL, or that a local audit chain detects every form of direct database tampering.
- Added keyboard focus trapping, Escape handling, focus restoration, and accessible dialog labels to the primary modal workflows.
