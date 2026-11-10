# TrustVault – Threat Model & Security Analysis

This document details the security risks, threat vectors, implemented countermeasures, and known boundaries of the TrustVault platform.

---

## 1. Threat Matrix & Mitigations

| Threat Vector | Severity | Vulnerability Description | TrustVault Mitigation |
| :--- | :--- | :--- | :--- |
| **Unauthorized Privilege Escalation** | Critical | Attacker submits `role: "admin"` during public registration to gain administrative control. | Public `/api/auth/register` rejects `admin` assignment with HTTP 403 and writes an `ACCESS_DENIED` event. Administrator creation is available only through the private CLI provisioning command; no public setup API or UI exists. |
| **Insecure Direct Object Reference (IDOR)** | Critical | Attacker alters document IDs in URL parameters (`/api/documents/:id/download`) to access private files of other users. | Every request undergoes server-side ownership and permission verification via `requireDocPermission` middleware against SQLite. IDs are strictly parsed and direct document IDs provide no access unless owned or actively shared. |
| **Malicious File Upload / Polyglots** | High | Attacker uploads an executable or script disguised with a supported file extension. | Multer limits uploads to 10 MiB. The server validates file contents, UTF-8 for text, and DOCX ZIP entry structure; unsupported extensions and spoofed signatures are rejected. File data remains outside the public frontend directory. |
| **Public Directory Traversal / Direct Asset Exposure** | High | Attackers crawl web roots or traverse file paths (`../../storage/documents/secret.pdf`) to leak confidential files. | Files are stored outside public web roots with cryptographically randomized filenames (`crypto.randomBytes(16).toString('hex')`). No static file middleware serves the storage folder; all downloads flow through authenticated Express route handlers with `path.basename` sanitization. |
| **Broken Access Control on Revocation** | High | Permissions revoked on the frontend remain cached or active on the backend, allowing continued file downloads. | Permission revocation removes the current SQLite record. Middleware checks current permission state on every download and view request; revoked access is immediately denied. |
| **Session Theft / XSS Token Exfiltration** | High | Cross-Site Scripting allows an attacker to extract session tokens from browser storage. | Tokens are not put in browser storage or API responses. A 256-bit random value is sent only in an HTTP-only, SameSite=Lax cookie; SQLite stores only its SHA-256 hash and expiration. |
| **SQL Injection** | High | Malicious SQL syntax in search filters or user input alters database execution. | ORM queries use bound parameters; the native SQLite adapter executes SQL with parameter arrays rather than string concatenation. |
| **Audit Trail Tampering** | Medium | A malicious actor or compromised service account alters historical access records to conceal unauthorized data exfiltration. | Audit hashes include the previous hash and record fields. Immediate SQLite transactions serialize writes and a trigger enforces chain continuity on inserts. Update/delete triggers reject ordinary application changes; verification detects altered records and broken links. A privileged local operator can disable triggers and rewrite or truncate the chain. |
| **On-Disk File Tampering** | Medium | An attacker or compromised local process alters a stored file on disk. | SHA-256 checksums are stored in SQLite and verified before download and inline view. Missing or changed files are not served. |
| **Administrator Abuse of Private Data** | Medium | A rogue system administrator reads confidential files belonging to other platform users. | The platform enforces an architectural privacy boundary: administrators have operational visibility over system metrics, audit logs, and account statuses, but lack default read/download access to users' private documents without explicit user grant. |
| **Cross-Site Request Forgery** | Medium | A third-party site attempts to issue authenticated state-changing requests using a victim's browser cookie. | State-changing `/api` requests require an exact matching `Origin` header; session cookies also use `SameSite=Lax`. No CORS access is enabled. This does not replace browser testing or deployment-specific reverse-proxy configuration. |
| **Login Brute Force** | Medium | Repeated password guesses target user accounts. | Five failed login attempts per client IP are allowed in a 15-minute window; further attempts receive HTTP 429. State is in-memory and per-process, so multi-process deployments require shared throttling. |
| **Data Exposure from Local Storage** | High | A person with access to the host filesystem reads stored document bytes or SQLite data. | Storage directories/files use restrictive permissions where supported by the host. The application does not encrypt files or the database at rest; host access controls and disk encryption remain deployment responsibilities. |

---

## 2. Cryptographic Hash Chaining Limitations & Protections

### Mathematical Detection Capability
TrustVault links every audit log via a SHA-256 hash pointer:
- Genesis Record: `prevHash = 0000000000000000000000000000000000000000000000000000000000000000`
- Subsequent Record $N$:
  $$\text{recordHash}_N = \text{SHA-256}(\text{recordHash}_{N-1} \parallel \text{userId} \parallel \text{action} \parallel \text{documentId} \parallel \text{result} \parallel \text{timestamp} \parallel \text{details})$$

If an attacker changes an existing record without recomputing dependent hashes, verification detects a hash mismatch or broken link. This does not guarantee detection of tail truncation or a complete rewrite by someone with direct database access. The built-in `/api/admin/audit-logs/verify` endpoint checks the records currently present in SQLite; it has no external trusted checkpoint.

### The Privileged DBA Threat Vector
**Crucial Security Reality**: Hash chaining and SQLite immutability triggers do **not** prevent a person with direct access to the local SQLite file from disabling triggers and recomputing hashes from the point of modification forward to the chain head.

### Recommended Defense-in-Depth Measures:
1. **Write-Once-Read-Many (WORM) External Storage**: Stream audit records to immutable cloud storage (such as Google Cloud Storage with Object Retention / Bucket Lock) where object modification and deletion are cryptographically and policy-blocked.
2. **Offsite SIEM Streaming**: In a production deployment, forward every audit event to an independently administered append-only log service where the database operator has no administrative access.
3. **Periodic Anchor Checkpointing**: Publish the latest `chainHeadHash` periodically to an external timestamping service or public cryptographic ledger so that retroactive re-hashing of the audit chain can be objectively disproven.

---

## 3. Remaining System Limitations & Hardening Guidelines

1. **Storage Encryption-at-Rest**: TrustVault uses local SQLite and filesystem storage; protection depends on host permissions and disk encryption. For sensitive production use, encrypt the database and document data at rest with managed keys.
2. **Rate Limiting & Brute-Force Throttling**: The application applies an in-memory limit of five failed login attempts per client IP per 15-minute window, cleared on successful login. It is process-local; multi-process deployments need a shared rate-limit store or reverse-proxy limit.
3. **Additional account protections**: Email verification, password reset, and multi-factor authentication are not implemented and would be future enhancements.
