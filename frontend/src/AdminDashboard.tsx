import { useEffect, useState } from 'react'
import type { FormEvent, ReactNode } from 'react'

import { ApiError, api, mutate } from './api'

type AdminUser = {
  id: string
  email: string
  is_admin: boolean
  is_active: boolean
  created_at: string
  disabled_at: string | null
}

type UserPage = {
  items: AdminUser[]
  total: number
  limit: number
  offset: number
}

type AdminDocument = {
  id: string
  filename: string
  owner_id: string
  owner_email: string
  size_bytes: number
  content_type: string
  created_at: string
  updated_at: string
}

type DocumentPage = {
  items: AdminDocument[]
  total: number
  limit: number
  offset: number
}

type AdminPermission = {
  id: string
  document_id: string
  filename: string
  owner_id: string
  owner_email: string
  user_id: string
  user_email: string
  access_level: string
  granted_at: string
  revoked_at: string | null
  status: 'active' | 'revoked' | 'legacy_inactive'
}

type PermissionPage = {
  items: AdminPermission[]
  total: number
  limit: number
  offset: number
}

type AuditEvent = {
  id: number
  actor_id: string | null
  actor_display_name: string | null
  actor_email: string | null
  actor_role: string | null
  document_id: string | null
  document_name: string | null
  permission_id: string | null
  permission_owner: string | null
  permission_viewer: string | null
  download_allowed: boolean | null
  permission_status: 'active' | 'revoked' | null
  target_display: string | null
  action_details: string | null
  action: string
  target_type: string
  target_id: string
  created_at: string
  metadata_json: string
  previous_hash: string
  event_hash: string
}

type AuditPage = {
  items: AuditEvent[]
  total: number
  limit: number
  offset: number
}

type AuditIntegrity = {
  is_valid: boolean
  event_count: number
  first_invalid_event_id: number | null
  failure_reason: 'event_order' | 'broken_link' | 'event_hash' | null
}

type Section = 'overview' | 'users' | 'documents' | 'permissions' | 'audit'

const PAGE_SIZE = 25
const sections: { id: Section; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'users', label: 'Users' },
  { id: 'documents', label: 'Documents' },
  { id: 'permissions', label: 'Permissions' },
  { id: 'audit', label: 'Audit log' },
]

function formatDate(value: string | null): string {
  if (!value) return '—'
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value))
}

function formatSize(size: number): string {
  if (size < 1024) return `${size} B`
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`
  return `${(size / (1024 * 1024)).toFixed(1)} MB`
}

function auditEventName(action: string): string {
  const knownNames: Record<string, string> = {
    'admin.user.activated': 'User Activated',
    'admin.user.deactivated': 'User Deactivated',
    'document.deleted': 'Document Deleted',
    'document.download_denied': 'Download Denied',
    'document.downloaded': 'Document Downloaded',
    'document.previewed': 'Document Previewed',
    'document.updated': 'Document Updated',
    'document.uploaded': 'Document Uploaded',
    'permission.download_updated': 'Download Permission Updated',
    'permission.granted': 'Permission Granted',
    'permission.revoked': 'Permission Revoked',
    'permission.updated': 'Permission Updated',
  }
  return (
    knownNames[action] ??
    action
      .split(/[._]/)
      .filter(Boolean)
      .map((word) => word[0].toUpperCase() + word.slice(1))
      .join(' ')
  )
}

function AdminDashboard({
  currentUserId,
  onSessionExpired,
}: {
  currentUserId: string
  onSessionExpired: () => void
}) {
  const [section, setSection] = useState<Section>('overview')
  const [page, setPage] = useState(0)
  const [loading, setLoading] = useState(false)
  const [refreshKey, setRefreshKey] = useState(0)
  const [busyUser, setBusyUser] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [overview, setOverview] = useState<{
    users: number
    activeUsers: number
    deactivatedUsers: number
    documents: number
    permissions: number
  } | null>(null)
  const [userPage, setUserPage] = useState<UserPage | null>(null)
  const [documentPage, setDocumentPage] = useState<DocumentPage | null>(null)
  const [permissionPage, setPermissionPage] = useState<PermissionPage | null>(
    null,
  )
  const [auditPage, setAuditPage] = useState<AuditPage | null>(null)
  const [auditIntegrity, setAuditIntegrity] = useState<AuditIntegrity | null>(
    null,
  )
  const [integrityLoading, setIntegrityLoading] = useState(false)
  const [integrityError, setIntegrityError] = useState('')
  const [selectedUser, setSelectedUser] = useState<AdminUser | null>(null)
  const [eventType, setEventType] = useState('')
  const [actorId, setActorId] = useState('')
  const [documentId, setDocumentId] = useState('')
  const [appliedFilters, setAppliedFilters] = useState({
    eventType: '',
    actorId: '',
    documentId: '',
  })

  function handleRequestError(cause: unknown, fallback: string) {
    if (
      cause instanceof ApiError &&
      (cause.status === 401 || cause.status === 403)
    ) {
      onSessionExpired()
      return
    }
    setError(cause instanceof Error ? cause.message : fallback)
  }

  useEffect(() => {
    let active = true
    setLoading(true)
    setError('')
    setSuccess('')

    async function load() {
      try {
        if (section === 'overview') {
          const [userResult, documentResult, permissionResult] =
            await Promise.all([
              api<UserPage>(`/admin/users?limit=${PAGE_SIZE}&offset=0`),
              api<DocumentPage>(`/admin/documents?limit=1&offset=0`),
              api<PermissionPage>(`/admin/permissions?limit=1&offset=0`),
            ])
          let activeUsers = 0
          for (let offset = 0; offset < userResult.total; offset += PAGE_SIZE) {
            const users =
              offset === 0
                ? userResult.items
                : (
                    await api<UserPage>(
                      `/admin/users?limit=${PAGE_SIZE}&offset=${offset}`,
                    )
                  ).items
            activeUsers += users.filter((user) => user.is_active).length
          }
          if (active) {
            setOverview({
              users: userResult.total,
              activeUsers,
              deactivatedUsers: userResult.total - activeUsers,
              documents: documentResult.total,
              permissions: permissionResult.total,
            })
          }
        } else if (section === 'users') {
          const result = await api<UserPage>(
            `/admin/users?limit=${PAGE_SIZE}&offset=${page * PAGE_SIZE}`,
          )
          if (active) setUserPage(result)
        } else if (section === 'documents') {
          const result = await api<DocumentPage>(
            `/admin/documents?limit=${PAGE_SIZE}&offset=${page * PAGE_SIZE}`,
          )
          if (active) setDocumentPage(result)
        } else if (section === 'permissions') {
          const result = await api<PermissionPage>(
            `/admin/permissions?limit=${PAGE_SIZE}&offset=${page * PAGE_SIZE}`,
          )
          if (active) setPermissionPage(result)
        } else {
          const params = new URLSearchParams({
            limit: String(PAGE_SIZE),
            offset: String(page * PAGE_SIZE),
          })
          if (appliedFilters.eventType) {
            params.set('event_type', appliedFilters.eventType)
          }
          if (appliedFilters.actorId) {
            params.set('user_id', appliedFilters.actorId)
          }
          if (appliedFilters.documentId) {
            params.set('document_id', appliedFilters.documentId)
          }
          const result = await api<AuditPage>(`/admin/audit?${params}`)
          if (active) setAuditPage(result)
        }
      } catch (cause) {
        if (active) handleRequestError(cause, 'Unable to load Admin data.')
      } finally {
        if (active) setLoading(false)
      }
    }

    void load()
    return () => {
      active = false
    }
  }, [section, page, appliedFilters, onSessionExpired, refreshKey])

  useEffect(() => {
    if (section !== 'audit') return

    let active = true
    setIntegrityLoading(true)
    setIntegrityError('')

    api<AuditIntegrity>('/admin/audit/integrity')
      .then((result) => {
        if (active) setAuditIntegrity(result)
      })
      .catch((cause: unknown) => {
        if (!active) return
        if (
          cause instanceof ApiError &&
          (cause.status === 401 || cause.status === 403)
        ) {
          onSessionExpired()
          return
        }
        setIntegrityError(
          cause instanceof Error
            ? cause.message
            : 'Unable to verify audit history.',
        )
      })
      .finally(() => {
        if (active) setIntegrityLoading(false)
      })

    return () => {
      active = false
    }
  }, [section, onSessionExpired, refreshKey])

  function selectSection(next: Section) {
    setSection(next)
    setPage(0)
    setError('')
    setSuccess('')
  }

  async function toggleUserStatus(user: AdminUser) {
    const nextActive = !user.is_active
    if (
      !nextActive &&
      !window.confirm(`Deactivate ${user.email}? Their active sessions will be revoked.`)
    ) {
      return
    }
    setBusyUser(user.id)
    setError('')
    setSuccess('')
    try {
      const updated = await mutate<AdminUser>(
        `/admin/users/${user.id}/status`,
        {
          method: 'PATCH',
          body: JSON.stringify({ is_active: nextActive }),
        },
      )
      setUserPage((current) =>
        current
          ? {
              ...current,
              items: current.items.map((item) =>
                item.id === updated.id ? updated : item,
              ),
            }
          : current,
      )
      setSelectedUser((current) =>
        current?.id === updated.id ? updated : current,
      )
      setSuccess(
        `${updated.email} ${updated.is_active ? 'activated' : 'deactivated'}.`,
      )
      if (overview) setOverview(null)
      if (updated.id === currentUserId && !updated.is_active) {
        onSessionExpired()
      }
    } catch (cause) {
      handleRequestError(cause, 'Unable to update account status.')
    } finally {
      setBusyUser(null)
    }
  }

  async function viewUser(user: AdminUser) {
    setError('')
    try {
      const details = await api<AdminUser>(`/admin/users/${user.id}`)
      setSelectedUser(details)
    } catch (cause) {
      handleRequestError(cause, 'Unable to load account details.')
    }
  }

  function applyAuditFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setPage(0)
    setAppliedFilters({
      eventType: eventType.trim(),
      actorId: actorId.trim(),
      documentId: documentId.trim(),
    })
  }

  return (
    <section className="mx-auto max-w-6xl px-4 py-8 sm:px-6">
      <div className="mb-6">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-moss">
          TrustVault administration
        </p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-ink">
          Admin dashboard
        </h1>
        <p className="mt-2 text-sm text-slate-600">
          Account, document metadata, permission, and audit oversight. Document
          contents are not available in this workspace.
        </p>
      </div>

      <nav
        aria-label="Admin dashboard sections"
        className="mb-6 flex gap-2 overflow-x-auto border-b border-slate-200 pb-2"
      >
        {sections.map((item) => (
          <button
            aria-current={section === item.id ? 'page' : undefined}
            className={`shrink-0 rounded-lg px-3 py-2 text-sm font-medium ${
              section === item.id
                ? 'bg-ink text-white'
                : 'text-slate-600 hover:bg-white hover:text-ink'
            }`}
            key={item.id}
            onClick={() => selectSection(item.id)}
            type="button"
          >
            {item.label}
          </button>
        ))}
      </nav>

      {success && (
        <p
          className="mb-4 rounded-xl bg-emerald-50 px-3 py-2 text-sm text-emerald-800"
          role="status"
        >
          {success}
        </p>
      )}
      {error && (
        <p
          className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-xl bg-red-50 px-3 py-2 text-sm text-red-800"
          role="alert"
        >
          <span>{error}</span>
          <button
            className="font-semibold underline"
            onClick={() => setRefreshKey((current) => current + 1)}
            type="button"
          >
            Retry
          </button>
        </p>
      )}

      {loading ? (
        <p className="rounded-2xl border border-slate-200 bg-white p-8 text-center text-sm text-slate-500">
          Loading Admin data…
        </p>
      ) : (
        <>
          {section === 'overview' && (
            <Overview
              onRetry={() => setRefreshKey((current) => current + 1)}
              overview={overview}
            />
          )}
          {section === 'users' && (
            <UsersSection
              onStatusChange={(user) => void toggleUserStatus(user)}
              onView={(user) => void viewUser(user)}
              page={userPage}
              pendingUser={busyUser}
              selectedUser={selectedUser}
              setSelectedUser={setSelectedUser}
              setPage={setPage}
              currentPage={page}
            />
          )}
          {section === 'documents' && (
            <DocumentsSection
              page={documentPage}
              setPage={setPage}
              currentPage={page}
            />
          )}
          {section === 'permissions' && (
            <PermissionsSection
              page={permissionPage}
              setPage={setPage}
              currentPage={page}
            />
          )}
          {section === 'audit' && (
            <AuditSection
              actorId={actorId}
              appliedFilters={appliedFilters}
              integrity={auditIntegrity}
              integrityError={integrityError}
              integrityLoading={integrityLoading}
              onRefresh={() => setRefreshKey((current) => current + 1)}
              onClearFilters={() => {
                setEventType('')
                setActorId('')
                setDocumentId('')
                setAppliedFilters({
                  eventType: '',
                  actorId: '',
                  documentId: '',
                })
                setPage(0)
              }}
              documentId={documentId}
              eventType={eventType}
              onFilterSubmit={applyAuditFilters}
              page={auditPage}
              setActorId={setActorId}
              setDocumentId={setDocumentId}
              setEventType={setEventType}
              setPage={setPage}
              currentPage={page}
            />
          )}
        </>
      )}
    </section>
  )
}

function Overview({
  overview,
  onRetry,
}: {
  overview: {
    users: number
    activeUsers: number
    deactivatedUsers: number
    documents: number
    permissions: number
  } | null
  onRetry: () => void
}) {
  if (!overview) {
    return (
      <EmptyState
        action={
          <button
            className="mt-3 rounded-lg border border-slate-300 px-3 py-2 text-sm font-medium text-ink"
            onClick={onRetry}
            type="button"
          >
            Retry
          </button>
        }
        text="Overview data is not available."
      />
    )
  }
  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <StatCard label="Total users" value={overview.users} />
      <StatCard label="Active users" value={overview.activeUsers} />
      <StatCard label="Deactivated users" value={overview.deactivatedUsers} />
      <StatCard label="Document metadata records" value={overview.documents} />
      <StatCard label="Permission records" value={overview.permissions} />
      <div className="rounded-2xl border border-slate-200 bg-white p-5 text-sm text-slate-600 sm:col-span-2 lg:col-span-3">
        This dashboard provides administrative metadata views only. It has no
        document preview, download, or content access.
      </div>
    </div>
  )
}

function StatCard({ label, value }: { label: string; value: number }) {
  return (
    <article className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
      <p className="text-sm text-slate-500">{label}</p>
      <p className="mt-2 text-3xl font-semibold tracking-tight text-ink">
        {value.toLocaleString()}
      </p>
    </article>
  )
}

function UsersSection({
  page,
  currentPage,
  setPage,
  onView,
  onStatusChange,
  pendingUser,
  selectedUser,
  setSelectedUser,
}: {
  page: UserPage | null
  currentPage: number
  setPage: (page: number) => void
  onView: (user: AdminUser) => void
  onStatusChange: (user: AdminUser) => void
  pendingUser: string | null
  selectedUser: AdminUser | null
  setSelectedUser: (user: AdminUser | null) => void
}) {
  if (!page || page.items.length === 0) {
    return <EmptyState text="No registered users were found." />
  }
  return (
    <div className="space-y-4">
      <div className="overflow-x-auto rounded-2xl border border-slate-200 bg-white shadow-sm">
        <table className="w-full min-w-[760px] text-left text-sm">
          <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-4 py-3">Account</th>
              <th className="px-4 py-3">Platform access</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Registered</th>
              <th className="px-4 py-3">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {page.items.map((user) => (
              <tr key={user.id}>
                <td className="px-4 py-3">
                  <p className="font-medium text-ink">{user.email}</p>
                  <p className="mt-1 break-all text-xs text-slate-500">
                    {user.id}
                  </p>
                </td>
                <td className="px-4 py-3">{user.is_admin ? 'Admin' : 'User'}</td>
                <td className="px-4 py-3">
                  <StatusBadge active={user.is_active}>
                    {user.is_active ? 'Active' : 'Deactivated'}
                  </StatusBadge>
                </td>
                <td className="px-4 py-3">{formatDate(user.created_at)}</td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-2">
                    <button
                      className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs font-medium text-ink"
                      onClick={() => onView(user)}
                      type="button"
                    >
                      View
                    </button>
                    <button
                      className="rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs font-medium text-ink disabled:opacity-50"
                      disabled={pendingUser === user.id}
                      onClick={() => onStatusChange(user)}
                      type="button"
                    >
                      {pendingUser === user.id
                        ? 'Please wait…'
                        : user.is_active
                          ? 'Deactivate'
                          : 'Activate'}
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Pagination
        currentPage={currentPage}
        onChange={setPage}
        page={page}
      />
      {selectedUser && (
        <div
          aria-labelledby="admin-user-detail-title"
          aria-modal="true"
          className="fixed inset-0 z-40 grid place-items-center bg-slate-950/50 p-4"
          role="dialog"
        >
          <section className="w-full max-w-lg rounded-2xl bg-white p-6 shadow-xl">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h2
                  className="text-xl font-semibold text-ink"
                  id="admin-user-detail-title"
                >
                  Account details
                </h2>
                <p className="mt-1 break-all text-sm text-slate-600">
                  {selectedUser.email}
                </p>
              </div>
              <button
                className="text-sm text-slate-600 underline"
                onClick={() => setSelectedUser(null)}
                type="button"
              >
                Close
              </button>
            </div>
            <dl className="mt-5 grid gap-3 text-sm sm:grid-cols-2">
              <Detail label="User ID" value={selectedUser.id} />
              <Detail
                label="Platform access"
                value={selectedUser.is_admin ? 'Admin' : 'Standard user'}
              />
              <Detail
                label="Account status"
                value={selectedUser.is_active ? 'Active' : 'Deactivated'}
              />
              <Detail
                label="Created"
                value={formatDate(selectedUser.created_at)}
              />
              <Detail
                label="Deactivated at"
                value={formatDate(selectedUser.disabled_at)}
              />
            </dl>
          </section>
        </div>
      )}
    </div>
  )
}

function DocumentsSection({
  page,
  currentPage,
  setPage,
}: {
  page: DocumentPage | null
  currentPage: number
  setPage: (page: number) => void
}) {
  if (!page || page.items.length === 0) {
    return <EmptyState text="No document metadata records were found." />
  }
  return (
    <div className="space-y-4">
      <div className="overflow-x-auto rounded-2xl border border-slate-200 bg-white shadow-sm">
        <table className="w-full min-w-[900px] text-left text-sm">
          <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-4 py-3">Document</th>
              <th className="px-4 py-3">Owner</th>
              <th className="px-4 py-3">Size / type</th>
              <th className="px-4 py-3">Created</th>
              <th className="px-4 py-3">Modified</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {page.items.map((document) => (
              <tr key={document.id}>
                <td className="px-4 py-3">
                  <p className="font-medium text-ink">{document.filename}</p>
                  <p className="mt-1 break-all text-xs text-slate-500">
                    {document.id}
                  </p>
                </td>
                <td className="px-4 py-3">
                  <p>{document.owner_email}</p>
                  <p className="mt-1 break-all text-xs text-slate-500">
                    {document.owner_id}
                  </p>
                </td>
                <td className="px-4 py-3">
                  <p>{formatSize(document.size_bytes)}</p>
                  <p className="mt-1 text-xs text-slate-500">
                    {document.content_type}
                  </p>
                </td>
                <td className="px-4 py-3">{formatDate(document.created_at)}</td>
                <td className="px-4 py-3">{formatDate(document.updated_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="text-xs text-slate-500">
        Metadata view only. Document contents, storage paths, preview, and
        downloads are not available to Admins.
      </p>
      <Pagination
        currentPage={currentPage}
        onChange={setPage}
        page={page}
      />
    </div>
  )
}

function PermissionsSection({
  page,
  currentPage,
  setPage,
}: {
  page: PermissionPage | null
  currentPage: number
  setPage: (page: number) => void
}) {
  if (!page || page.items.length === 0) {
    return <EmptyState text="No permission records were found." />
  }
  return (
    <div className="space-y-4">
      <div className="overflow-x-auto rounded-2xl border border-slate-200 bg-white shadow-sm">
        <table className="w-full min-w-[960px] text-left text-sm">
          <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-4 py-3">Document / owner</th>
              <th className="px-4 py-3">Recipient</th>
              <th className="px-4 py-3">Access</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Granted</th>
              <th className="px-4 py-3">Revoked</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {page.items.map((permission) => (
              <tr key={permission.id}>
                <td className="px-4 py-3">
                  <p className="font-medium text-ink">{permission.filename}</p>
                  <p className="mt-1 break-all text-xs text-slate-500">
                    {permission.document_id}
                  </p>
                  <p className="mt-1 text-xs text-slate-600">
                    Owner: {permission.owner_email}
                  </p>
                </td>
                <td className="px-4 py-3">
                  <p>{permission.user_email}</p>
                  <p className="mt-1 break-all text-xs text-slate-500">
                    {permission.user_id}
                  </p>
                </td>
                <td className="px-4 py-3">{permission.access_level}</td>
                <td className="px-4 py-3">
                  <PermissionStatus status={permission.status} />
                </td>
                <td className="px-4 py-3">{formatDate(permission.granted_at)}</td>
                <td className="px-4 py-3">{formatDate(permission.revoked_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Pagination
        currentPage={currentPage}
        onChange={setPage}
        page={page}
      />
    </div>
  )
}

function AuditSection({
  page,
  integrity,
  integrityError,
  integrityLoading,
  onRefresh,
  currentPage,
  setPage,
  eventType,
  actorId,
  documentId,
  setEventType,
  setActorId,
  setDocumentId,
  appliedFilters,
  onClearFilters,
  onFilterSubmit,
}: {
  page: AuditPage | null
  integrity: AuditIntegrity | null
  integrityError: string
  integrityLoading: boolean
  onRefresh: () => void
  currentPage: number
  setPage: (page: number) => void
  eventType: string
  actorId: string
  documentId: string
  setEventType: (value: string) => void
  setActorId: (value: string) => void
  setDocumentId: (value: string) => void
  appliedFilters: { eventType: string; actorId: string; documentId: string }
  onClearFilters: () => void
  onFilterSubmit: (event: FormEvent<HTMLFormElement>) => void
}) {
  return (
    <div className="space-y-4">
      <AuditIntegritySection
        error={integrityError}
        integrity={integrity}
        loading={integrityLoading}
        onRefresh={onRefresh}
      />
      <form
        className="grid gap-3 rounded-2xl border border-slate-200 bg-white p-4 sm:grid-cols-2 lg:grid-cols-4"
        onSubmit={onFilterSubmit}
      >
        <label className="text-xs font-medium text-slate-600">
          Event type
          <input
            className="mt-1 block w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
            onChange={(event) => setEventType(event.target.value)}
            placeholder="e.g. admin.user.deactivated"
            value={eventType}
          />
        </label>
        <label className="text-xs font-medium text-slate-600">
          Actor / user ID
          <input
            className="mt-1 block w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
            onChange={(event) => setActorId(event.target.value)}
            placeholder="UUID"
            value={actorId}
          />
        </label>
        <label className="text-xs font-medium text-slate-600">
          Document ID
          <input
            className="mt-1 block w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
            onChange={(event) => setDocumentId(event.target.value)}
            placeholder="UUID"
            value={documentId}
          />
        </label>
        <div className="flex items-end gap-2">
          <button
            className="rounded-lg bg-ink px-3 py-2 text-sm font-semibold text-white"
            type="submit"
          >
            Apply filters
          </button>
          <button
            className="rounded-lg border border-slate-300 px-3 py-2 text-sm font-medium text-ink"
            onClick={onClearFilters}
            type="button"
          >
            Clear
          </button>
        </div>
      </form>

      <p className="text-xs text-slate-500">
        Read-only audit history
        {appliedFilters.eventType ? ` · ${appliedFilters.eventType}` : ''}
      </p>
      {!page || page.items.length === 0 ? (
        <EmptyState text="No audit events match the current filters." />
      ) : (
        <>
          <div className="space-y-3">
            {page.items.map((event) => (
              <article
                className="overflow-hidden rounded-2xl border border-slate-200 bg-white p-4 shadow-sm"
                key={event.id}
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="font-semibold text-ink">
                      {auditEventName(event.action)}
                    </p>
                    <p className="mt-1 text-xs text-slate-500">
                      {formatDate(event.created_at)}
                    </p>
                  </div>
                  <span className="text-xs text-slate-500">Event #{event.id}</span>
                </div>
                <dl className="mt-3 grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
                  <div className="min-w-0">
                    <dt className="text-xs font-medium text-slate-500">Actor</dt>
                    <dd className="mt-0.5 break-words font-medium text-ink">
                      {event.actor_display_name &&
                      event.actor_display_name !== event.actor_email
                        ? event.actor_display_name
                        : event.actor_email ??
                          (event.actor_id ? 'Deleted User' : 'System')}
                    </dd>
                    {event.actor_display_name &&
                      event.actor_email &&
                      event.actor_email !== event.actor_display_name && (
                        <dd className="mt-0.5 break-all text-xs text-slate-500">
                          {event.actor_email}
                        </dd>
                      )}
                    {event.actor_role === 'Admin' && (
                      <dd className="mt-0.5 text-xs text-slate-500">Admin</dd>
                    )}
                  </div>
                  {event.document_name && (
                    <div className="min-w-0">
                      <dt className="text-xs font-medium text-slate-500">
                        Document
                      </dt>
                      <dd className="mt-0.5 break-words text-ink">
                        {event.document_name}
                      </dd>
                    </div>
                  )}
                  {event.target_display &&
                    !event.document_name &&
                    !event.permission_viewer && (
                      <div className="min-w-0">
                        <dt className="text-xs font-medium text-slate-500">
                          Target
                        </dt>
                        <dd className="mt-0.5 break-words text-ink">
                          {event.target_display}
                        </dd>
                      </div>
                    )}
                  {event.permission_viewer && (
                    <>
                      <div className="min-w-0">
                        <dt className="text-xs font-medium text-slate-500">
                          Owner
                        </dt>
                        <dd className="mt-0.5 break-words text-ink">
                          {event.permission_owner ?? 'Unavailable'}
                        </dd>
                      </div>
                      <div className="min-w-0">
                        <dt className="text-xs font-medium text-slate-500">
                          Viewer
                        </dt>
                        <dd className="mt-0.5 break-words text-ink">
                          {event.permission_viewer}
                        </dd>
                      </div>
                      {event.download_allowed !== null && (
                        <div>
                          <dt className="text-xs font-medium text-slate-500">
                            Download permission
                          </dt>
                          <dd className="mt-0.5 text-ink">
                            {event.download_allowed ? 'Allowed' : 'Denied'}
                          </dd>
                        </div>
                      )}
                      {event.permission_status && (
                        <div>
                          <dt className="text-xs font-medium text-slate-500">
                            Permission status
                          </dt>
                          <dd className="mt-0.5 capitalize text-ink">
                            {event.permission_status}
                          </dd>
                        </div>
                      )}
                    </>
                  )}
                </dl>
                {event.action_details && (
                  <p className="mt-3 text-xs text-slate-600">
                    {event.action_details}
                  </p>
                )}
                <details className="mt-3">
                  <summary className="cursor-pointer text-xs font-medium text-moss">
                    Technical Details and Hash Chain
                  </summary>
                  <dl className="mt-3 grid gap-3 text-xs">
                    <Detail
                      label="Actor UUID"
                      value={event.actor_id ?? 'Unavailable in this audit record'}
                    />
                    {event.document_id && (
                      <Detail label="Document UUID" value={event.document_id} />
                    )}
                    {event.permission_id && (
                      <Detail
                        label="Document Permission UUID"
                        value={event.permission_id}
                      />
                    )}
                    {event.target_type !== 'document' &&
                      event.target_type !== 'document_permission' && (
                        <Detail
                          label="Target UUID / ID"
                          value={event.target_id}
                        />
                      )}
                    <Detail label="Original Event Type" value={event.action} />
                    <Detail label="Metadata" value={event.metadata_json} />
                    <Detail
                      label="Previous Event Hash"
                      value={event.previous_hash}
                    />
                    <Detail label="Event Hash" value={event.event_hash} />
                  </dl>
                </details>
              </article>
            ))}
          </div>
          <Pagination
            currentPage={currentPage}
            onChange={setPage}
            page={page}
          />
        </>
      )}
    </div>
  )
}

function AuditIntegritySection({
  integrity,
  loading,
  error,
  onRefresh,
}: {
  integrity: AuditIntegrity | null
  loading: boolean
  error: string
  onRefresh: () => void
}) {
  return (
    <section
      aria-labelledby="audit-integrity-heading"
      className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm"
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2
            className="font-semibold text-ink"
            id="audit-integrity-heading"
          >
            Audit integrity
          </h2>
          <p className="mt-1 text-xs text-slate-600">
            Read-only verification of event ordering, hashes, and chain links.
          </p>
        </div>
        <button
          className="rounded-lg border border-slate-300 px-3 py-1.5 text-sm font-medium text-ink disabled:opacity-50"
          disabled={loading}
          onClick={onRefresh}
          type="button"
        >
          {loading ? 'Checking…' : 'Refresh integrity'}
        </button>
      </div>

      {loading ? (
        <p aria-live="polite" className="mt-4 text-sm text-slate-500">
          Checking audit history…
        </p>
      ) : error ? (
        <p className="mt-4 text-sm text-red-700" role="alert">
          {error}
        </p>
      ) : integrity ? (
        <>
          <div className="mt-4 flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
            <p>
              Status:{' '}
              <StatusBadge active={integrity.is_valid}>
                {integrity.is_valid ? 'Valid' : 'Invalid'}
              </StatusBadge>
            </p>
            <p className="text-slate-600">
              Events checked: {integrity.event_count}
            </p>
          </div>
          {integrity.event_count === 0 && (
            <p className="mt-3 text-sm text-slate-600">
              No audit events have been recorded yet.
            </p>
          )}
          {!integrity.is_valid && (
            <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
              {integrity.first_invalid_event_id !== null && (
                <Detail
                  label="First invalid event"
                  value={`Event #${integrity.first_invalid_event_id}`}
                />
              )}
              {integrity.failure_reason && (
                <Detail
                  label="Failure reason"
                  value={integrity.failure_reason.replaceAll('_', ' ')}
                />
              )}
            </dl>
          )}
        </>
      ) : (
        <p className="mt-4 text-sm text-slate-500">
          Integrity status is not available yet.
        </p>
      )}

      <p className="mt-4 border-t border-slate-100 pt-3 text-xs text-slate-500">
        A valid chain does not prove that the entire history was never truncated
        or rewritten by someone with database-level privileges. No secrets or
        signing keys are displayed here.
      </p>
    </section>
  )
}

function Pagination({
  page,
  currentPage,
  onChange,
}: {
  page: { total: number; limit: number; offset: number }
  currentPage: number
  onChange: (page: number) => void
}) {
  const lastPage = Math.max(0, Math.ceil(page.total / page.limit) - 1)
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-slate-600">
      <span>
        {page.total === 0
          ? 'No records'
          : `${page.offset + 1}–${Math.min(page.offset + page.limit, page.total)} of ${page.total}`}
      </span>
      <div className="flex gap-2">
        <button
          className="rounded-lg border border-slate-300 px-3 py-1.5 disabled:opacity-50"
          disabled={currentPage === 0}
          onClick={() => onChange(Math.max(0, currentPage - 1))}
          type="button"
        >
          Previous
        </button>
        <button
          className="rounded-lg border border-slate-300 px-3 py-1.5 disabled:opacity-50"
          disabled={currentPage >= lastPage}
          onClick={() => onChange(Math.min(lastPage, currentPage + 1))}
          type="button"
        >
          Next
        </button>
      </div>
    </div>
  )
}

function StatusBadge({
  active,
  children,
}: {
  active: boolean
  children: ReactNode
}) {
  return (
    <span
      className={`rounded-full px-2.5 py-1 text-xs font-medium ${
        active ? 'bg-emerald-50 text-emerald-800' : 'bg-slate-100 text-slate-600'
      }`}
    >
      {children}
    </span>
  )
}

function PermissionStatus({
  status,
}: {
  status: AdminPermission['status']
}) {
  if (status === 'legacy_inactive') {
    return (
      <span className="rounded-full bg-amber-50 px-2.5 py-1 text-xs font-medium text-amber-800">
        Legacy inactive
      </span>
    )
  }
  return <StatusBadge active={status === 'active'}>{status}</StatusBadge>
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="font-medium text-slate-500">{label}</dt>
      <dd className="mt-1 break-all text-ink">{value}</dd>
    </div>
  )
}

function EmptyState({
  text,
  action,
}: {
  text: string
  action?: ReactNode
}) {
  return (
    <div className="rounded-2xl border border-dashed border-slate-300 bg-white p-8 text-center text-sm text-slate-500">
      <p>{text}</p>
      {action}
    </div>
  )
}

export default AdminDashboard
