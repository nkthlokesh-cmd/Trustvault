# TrustVault – Secure Document Sharing Platform

TrustVault is a local-first document management and sharing application. Owners upload private documents and grant registered users READ or EDIT access. Administrators manage accounts and audit activity, but do not receive automatic access to private files.

## Features

- Separate Administrator, Owner, and Viewer dashboards.
- Public owner/viewer registration, password login, and logout.
- bcrypt password hashing and 24-hour HTTP-only, SameSite=Lax session cookies. Raw session tokens are never returned by the API or stored in SQLite.
- SQLite persistence for users, documents, permissions, sessions, and audit records. The database is created on first startup; foreign keys and a five-second busy timeout are enabled.
- Private file storage, random server-side filenames, supported-content checks, SHA-256 file checksums, and access checks on every document request.
- Five failed login attempts per client IP are allowed in a 15-minute window; successful login clears the counter. State-changing API requests require a matching same-origin `Origin` header.
- READ/EDIT permission management with immediate revocation.
- SHA-256 hash-linked, immutable-through-the-app audit records and an administrator chain-verification endpoint.
- Private administrator provisioning through a CLI command only. There is no public administrator setup endpoint or page.

## Technologies

- React 19, TypeScript, Vite, Tailwind CSS, Lucide icons, Motion.
- Node.js, Express, Drizzle ORM, Node's built-in SQLite engine, bcryptjs, Multer.

## Project structure

```text
src/
  components/       React dashboards, forms, and document modals
  context/          Authentication and notification state
  db/               SQLite schema, connection, and Drizzle configuration
  server/           Authentication, permissions, documents, audit, storage, and admin CLI
  types/            Shared TypeScript types
tests/              Backend API and SQLite security tests
server.ts           Express API and development/production frontend startup
```

## Prerequisites

- Node.js 22.16 or newer (the application uses Node's built-in `node:sqlite` module).
- npm.

No PostgreSQL service, cloud database, or external API is required.

## Setup

In PowerShell:

```powershell
Copy-Item .env.example .env
npm install
```

The default SQLite database path is `./data/trustvault.sqlite`. `DATA_DIR` and `SQLITE_DB_PATH` may be set in `.env`; the parent directory and tables are created automatically. The private document directory defaults to `./data/documents` and can be changed with `STORAGE_DIR`. Keep both data locations out of public/static frontend directories and back them up separately.

There are no SQL migrations to run for a new local database. The application creates the current schema at startup.

## Starting the application

Development mode serves the React application and API together at `http://localhost:3000`:

```powershell
npm run dev
```

For a production build:

```powershell
npm run build
$env:NODE_ENV = "production"
npm start
```

The production server serves the generated `dist/` frontend and the same API.

## Administrator provisioning and demo accounts

Administrator creation is deliberately not available from the public website or API. Configure these values temporarily in the process environment or a private, ignored `.env` file:

- `TRUSTVAULT_ADMIN_EMAIL`
- `TRUSTVAULT_ADMIN_NAME`
- `TRUSTVAULT_ADMIN_PASSWORD`

Then run:

```powershell
npm run admin:create
```

The password must contain at least eight characters with uppercase, lowercase, a number, and a symbol. Provisioning is idempotent: if an administrator already exists, it reports that fact and never changes the existing password. Remove temporary provisioning values after use. Do not commit `.env` or use real credentials in demos.

Create demo Owner and Viewer accounts through the registration form. Share an Owner document with the Viewer to demonstrate READ, EDIT, and revocation behavior. Admin accounts must be created with the CLI.

For an isolated demonstration that does not use the checked-in database, configure unique temporary paths before provisioning or starting the server:

```powershell
$demoRoot = Join-Path $env:TEMP ("trustvault-demo-" + [guid]::NewGuid().ToString("N"))
$env:DATA_DIR = Join-Path $demoRoot "data"
$env:SQLITE_DB_PATH = Join-Path $env:DATA_DIR "trustvault.sqlite"
$env:STORAGE_DIR = Join-Path $env:DATA_DIR "documents"
$env:TRUSTVAULT_ADMIN_EMAIL = "admin@example.test"
$env:TRUSTVAULT_ADMIN_NAME = "Demo Administrator"
$securePassword = Read-Host "Demo admin password" -AsSecureString
$env:TRUSTVAULT_ADMIN_PASSWORD = [System.Net.NetworkCredential]::new("", $securePassword).Password
npm run admin:create
Remove-Item Env:TRUSTVAULT_ADMIN_EMAIL, Env:TRUSTVAULT_ADMIN_NAME, Env:TRUSTVAULT_ADMIN_PASSWORD
npm run dev
```

Register a demo Owner and Viewer in the browser, then upload a non-sensitive sample document as Owner, grant READ and EDIT in turn, and revoke access to demonstrate denial on the next request. The temporary directory is separate from the project's existing database and files. Keep it if needed for the demo; delete it manually only when you no longer need its data.

## SQLite configuration

`.env.example` contains non-secret defaults:

```env
DATA_DIR="./data"
SQLITE_DB_PATH="./data/trustvault.sqlite"
STORAGE_DIR="./data/documents"
COOKIE_SECURE="false"
NODE_ENV="development"
```

For an HTTPS deployment, set `COOKIE_SECURE=true`. SQLite foreign-key enforcement is enabled for the application connection, writes wait up to five seconds for a lock, and WAL mode is used for local concurrency.
When TLS terminates at a reverse proxy, set `TRUSTVAULT_APP_ORIGIN` to the canonical browser origin (for example `https://trustvault.example.edu`) so state-changing requests can be checked against the public origin. The application is same-origin and does not enable CORS.

## Database and document backups

Backups are not automated. Stop the application cleanly, then copy the SQLite database at `SQLITE_DB_PATH` and the complete `STORAGE_DIR` together to a private backup location. Keep database and files from the same backup point so document metadata continues to match stored content. Protect backups with host/disk access controls; the application does not encrypt them.

## API overview

All API routes are under `/api`. Authenticated requests use the HTTP-only `trustvault_session` cookie; bearer tokens are not accepted.

| Area | Routes | Access |
|---|---|---|
| Authentication | `POST /auth/register`, `POST /auth/login`, `POST /auth/logout`, `GET /auth/me` | Register/login public; logout and `/me` use the session |
| Documents | `GET /documents`, `POST /documents/upload`, `GET /documents/:id`, `PUT /documents/:id`, `DELETE /documents/:id`, `GET /documents/:id/download`, `GET /documents/:id/view` | Session required; document access follows owner/share permission |
| Sharing | `GET /permissions/users`, `POST /permissions/:id/grant`, `DELETE /permissions/:id/revoke/:targetUserId` | Owner only |
| Administration | `GET /admin/stats`, `GET /admin/users`, `PATCH /admin/users/:id/status`, `GET /admin/audit-logs`, `GET /admin/audit-logs/verify`, `GET /admin/sharing-monitor` | Administrator only |
| Health | `GET /api/health` | Public |

Public registration only creates Owner or Viewer accounts. Successful login sets a cookie and returns user information, never the session token. Admin document listings expose metadata only; private file access still requires ownership or an explicitly granted permission.

## Supported uploads

PDF, DOCX, TXT, PNG, JPG, and JPEG; maximum file size is 10 MiB. The server checks file contents (including DOCX archive entries), enforces the size limit, uses a random storage filename, and stores the original name only as metadata.

## Tests and checks

```powershell
npm test
npm run lint
npm run build
```

The backend tests create an isolated temporary SQLite database and API server. They cover database initialization/integrity and foreign keys, reopen persistence, rollback, registration/login/logout, cookie-only authentication, role boundaries, upload validation/size and cleanup, sharing and immediate revocation, admin privacy and status controls, origin checks, login throttling, and audit-chain verification/concurrent writes.

`npm run lint` runs `tsc --noEmit`; no ESLint configuration or ESLint script is currently included.

## Known limitations

- SQLite and local file storage are intended for a single-machine demonstration, not a horizontally scaled or high-write production deployment.
- Audit writes use SQLite immediate transactions and a chain-continuity insert trigger to serialize chain-head updates across processes using the same database. This does not prevent a privileged local operator from disabling triggers or rewriting/truncating the database; no external audit anchor is configured.
- File signature and DOCX structure checks do not replace antivirus scanning or document sanitization. File checksums provide integrity detection, not encryption; files and SQLite data are not encrypted at rest by the application.
- The project does not include automated browser/UI tests, email verification, password reset, multi-factor authentication, or application-level encryption at rest. The login limiter is in-memory and per-process; use shared throttling for a multi-process deployment.
- State-changing API requests require an exact matching `Origin`. Behind TLS termination, configure `TRUSTVAULT_APP_ORIGIN` to the public application origin.
