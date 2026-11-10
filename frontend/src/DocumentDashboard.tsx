import { useEffect, useRef, useState } from 'react'
import type { ChangeEvent, FormEvent, ReactNode } from 'react'

import { api, apiResponse, mutate } from './api'

type DocumentItem = {
  id: string
  name: string
  category: string
  filename: string
  content_type: string
  size_bytes: number
  created_at: string
  owner_email: string
}

type PermissionItem = {
  id: string
  user_id: string
  user_email: string
  access_level: 'read' | 'edit'
  can_download: boolean
  created_at: string
}

type SharedDocumentItem = DocumentItem & {
  access_level: 'read'
  can_download: boolean
}

const PREDEFINED_CATEGORIES = [
  'Uncategorized',
  'Personal',
  'Work',
  'Financial',
  'Legal',
  'Medical',
  'Education',
  'Tax',
  'Insurance',
  'Other',
]

type CategoryFieldProps = {
  id: string
  value: string
  options: string[]
  onChange: (value: string) => void
}

function CategoryField({ id, value, options, onChange }: CategoryFieldProps) {
  const [open, setOpen] = useState(false)
  const [activeIndex, setActiveIndex] = useState(-1)
  const fieldRef = useRef<HTMLDivElement>(null)
  const filteredOptions = options.filter((option) =>
    option.toLowerCase().includes(value.toLowerCase()),
  )
  const customValue = value.trim()
  const hasCustomValue =
    customValue.length > 0 &&
    !options.some((option) => option.toLowerCase() === customValue.toLowerCase())
  const visibleOptions = hasCustomValue
    ? [customValue, ...filteredOptions]
    : filteredOptions
  const listId = `${id}-options`

  function chooseCategory(option: string) {
    onChange(option)
    setOpen(false)
    setActiveIndex(-1)
  }

  return (
    <div
      className="relative mt-1.5"
      onBlur={(event) => {
        const nextTarget = event.relatedTarget
        if (!(nextTarget instanceof Node) || !fieldRef.current?.contains(nextTarget)) {
          setOpen(false)
        }
      }}
      ref={fieldRef}
    >
      <div className="flex">
        <input
          aria-activedescendant={
            open && activeIndex >= 0
              ? `${listId}-option-${activeIndex}`
              : undefined
          }
          aria-autocomplete="list"
          aria-controls={listId}
          aria-expanded={open}
          autoComplete="off"
          className="min-w-0 flex-1 rounded-l-xl border border-slate-300 px-3 py-2 text-sm"
          id={id}
          maxLength={80}
          onChange={(event) => {
            onChange(event.target.value)
            setOpen(true)
            setActiveIndex(-1)
          }}
          onFocus={() => setOpen(true)}
          onKeyDown={(event) => {
            if (event.key === 'Escape') {
              setOpen(false)
            } else if (event.key === 'ArrowDown' && visibleOptions.length > 0) {
              event.preventDefault()
              setOpen(true)
              setActiveIndex((index) =>
                index < visibleOptions.length - 1 ? index + 1 : 0,
              )
            } else if (event.key === 'ArrowUp' && visibleOptions.length > 0) {
              event.preventDefault()
              setOpen(true)
              setActiveIndex((index) =>
                index > 0 ? index - 1 : visibleOptions.length - 1,
              )
            } else if (
              event.key === 'Enter' &&
              open &&
              activeIndex >= 0 &&
              visibleOptions[activeIndex]
            ) {
              event.preventDefault()
              chooseCategory(visibleOptions[activeIndex])
            }
          }}
          required
          role="combobox"
          value={value}
        />
        <button
          aria-label={open ? 'Hide category options' : 'Show category options'}
          aria-expanded={open}
          className="shrink-0 rounded-r-xl border border-l-0 border-slate-300 px-3 text-slate-500 hover:bg-paper hover:text-ink"
          onClick={() => setOpen((currentlyOpen) => !currentlyOpen)}
          type="button"
        >
          <svg aria-hidden="true" className="h-4 w-4" fill="none" viewBox="0 0 20 20">
            <path d="m5 7.5 5 5 5-5" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.7" />
          </svg>
        </button>
      </div>
      {open && (
        <div
          className="absolute z-20 mt-1 max-h-[220px] w-full overflow-y-auto overscroll-contain rounded-xl border border-slate-200 bg-white py-1 shadow-lg [touch-action:pan-y]"
          id={listId}
          role="listbox"
        >
          {visibleOptions.map((option, index) => (
            <div
              aria-selected={option === value}
              className={`cursor-pointer px-3 py-2 text-sm ${
                index === activeIndex
                  ? 'bg-paper text-ink'
                  : 'text-slate-700 hover:bg-paper'
              }`}
              id={`${listId}-option-${index}`}
              key={`${option}-${index}`}
              onClick={() => chooseCategory(option)}
              onMouseDown={(event) => event.preventDefault()}
              role="option"
            >
              {hasCustomValue && index === 0
                ? `Use "${option}" (custom)`
                : option}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function formatSize(size: number): string {
  if (size < 1024) return `${size} B`
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`
  return `${(size / (1024 * 1024)).toFixed(1)} MB`
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value))
}

type DocumentAction = 'preview' | 'download' | 'edit' | 'share' | 'delete' | 'revoke'

const DOCUMENT_ACTION_LABELS: Record<DocumentAction, string> = {
  preview: 'Preview',
  download: 'Download',
  edit: 'Edit',
  share: 'Share',
  delete: 'Delete',
  revoke: 'Revoke access',
}

function DocumentActionButton({
  action,
  disabled,
  onClick,
}: {
  action: DocumentAction
  disabled?: boolean
  onClick: () => void
}) {
  const label = DOCUMENT_ACTION_LABELS[action]
  const iconPaths: Record<DocumentAction, ReactNode> = {
    preview: (
      <>
        <path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6Z" />
        <circle cx="12" cy="12" r="2.5" />
      </>
    ),
    download: (
      <>
        <path d="M12 3v12m0 0 4-4m-4 4-4-4" />
        <path d="M4 17v3h16v-3" />
      </>
    ),
    edit: (
      <>
        <path d="m14 5 5 5M4 20l4.5-1 11-11a2.1 2.1 0 0 0-3-3l-11 11L4 20Z" />
      </>
    ),
    share: (
      <>
        <circle cx="18" cy="5" r="2.5" />
        <circle cx="6" cy="12" r="2.5" />
        <circle cx="18" cy="19" r="2.5" />
        <path d="m8.2 10.8 7.6-4.5m-7.6 7.9 7.6 4.5" />
      </>
    ),
    delete: (
      <>
        <path d="M4 7h16M10 11v6m4-6v6M6 7l1 14h10l1-14M9 7V4h6v3" />
      </>
    ),
    revoke: (
      <>
        <path d="M6 6l12 12M18 6 6 18" />
        <circle cx="12" cy="12" r="9" />
      </>
    ),
  }
  const isDelete = action === 'delete' || action === 'revoke'

  return (
    <button
      aria-label={label}
      className={`group relative inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 disabled:cursor-not-allowed disabled:opacity-50 ${
        isDelete
          ? 'border-red-200 text-red-700 hover:bg-red-50 focus-visible:outline-red-600'
          : 'border-slate-300 text-ink hover:bg-paper focus-visible:outline-ink'
      }`}
      disabled={disabled}
      onClick={onClick}
      type="button"
    >
      <svg
        aria-hidden="true"
        className="h-4 w-4"
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.7"
        viewBox="0 0 24 24"
      >
        {iconPaths[action]}
      </svg>
      <span
        className="pointer-events-none absolute bottom-full left-1/2 z-20 mb-2 -translate-x-1/2 whitespace-nowrap rounded-md bg-slate-900 px-2 py-1 text-xs font-medium text-white opacity-0 shadow transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100"
        role="tooltip"
      >
        {label}
      </span>
    </button>
  )
}

function DocumentDashboard() {
  const [documents, setDocuments] = useState<DocumentItem[]>([])
  const [sharedDocuments, setSharedDocuments] = useState<SharedDocumentItem[]>([])
  const categoryOptions = [
    ...new Set([
      ...PREDEFINED_CATEGORIES,
      ...documents.map((item) => item.category),
      ...sharedDocuments.map((item) => item.category),
    ]),
  ]
  const [search, setSearch] = useState('')
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [displayName, setDisplayName] = useState('')
  const [category, setCategory] = useState('Uncategorized')
  const [editing, setEditing] = useState<string | null>(null)
  const [sharing, setSharing] = useState<string | null>(null)
  const [permissions, setPermissions] = useState<PermissionItem[]>([])
  const [shareEmail, setShareEmail] = useState('')
  const [shareCanDownload, setShareCanDownload] = useState(false)
  const [previewing, setPreviewing] = useState<DocumentItem | null>(null)
  const [previewUrl, setPreviewUrl] = useState<string | null>(null)
  const [previewText, setPreviewText] = useState('')
  const [previewLoading, setPreviewLoading] = useState(false)
  const [previewError, setPreviewError] = useState('')
  const [editName, setEditName] = useState('')
  const [editCategory, setEditCategory] = useState('')
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    if (!previewing) {
      setPreviewUrl(null)
      setPreviewText('')
      setPreviewError('')
      return
    }

    let active = true
    let objectUrl: string | null = null
    setPreviewLoading(true)
    setPreviewError('')
    setPreviewUrl(null)
    setPreviewText('')

    void (async () => {
      try {
        const response = await apiResponse(
          `/documents/${previewing.id}/preview`,
        )

        if (
          previewing.content_type === 'text/plain' ||
          previewing.content_type ===
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ) {
          const text = await response.text()
          if (active) setPreviewText(text)
        } else {
          objectUrl = URL.createObjectURL(await response.blob())
          if (active) setPreviewUrl(objectUrl)
        }
      } catch (cause) {
        if (active) {
          setPreviewError(
            cause instanceof Error ? cause.message : 'Unable to preview document.',
          )
        }
      } finally {
        if (active) setPreviewLoading(false)
      }
    })()

    return () => {
      active = false
      if (objectUrl) URL.revokeObjectURL(objectUrl)
    }
  }, [previewing])

  useEffect(() => {
    let active = true
    setLoading(true)
    const query = search.trim()
      ? `?search=${encodeURIComponent(search.trim())}`
      : ''
    void Promise.all([
      api<DocumentItem[]>(`/documents${query}`),
      api<SharedDocumentItem[]>('/documents/shared'),
    ])
      .then(([result, shared]) => {
        if (active) {
          setDocuments(result)
          setSharedDocuments(shared)
          setError('')
        }
      })
      .catch((cause: unknown) => {
        if (active) {
          setError(
            cause instanceof Error ? cause.message : 'Unable to load documents.',
          )
        }
      })
      .finally(() => {
        if (active) setLoading(false)
      })
    return () => {
      active = false
    }
  }, [search])

  function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    setSelectedFile(event.target.files?.[0] ?? null)
    setMessage('')
    setError('')
  }

  async function handleUpload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!selectedFile) return
    setBusy(true)
    setMessage('')
    setError('')
    const data = new FormData()
    data.set('file', selectedFile)
    data.set('category', category)
    if (displayName.trim()) data.set('name', displayName.trim())
    try {
      await mutate<DocumentItem>('/documents', { method: 'POST', body: data })
      setSelectedFile(null)
      setDisplayName('')
      setCategory('Uncategorized')
      const input = document.getElementById('document-upload')
      if (input instanceof HTMLInputElement) input.value = ''
      setMessage('Document uploaded successfully.')
      await refreshDocuments()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to upload document.')
    } finally {
      setBusy(false)
    }
  }

  async function refreshDocuments() {
    const query = search.trim()
      ? `?search=${encodeURIComponent(search.trim())}`
      : ''
    try {
      const [result, shared] = await Promise.all([
        api<DocumentItem[]>(`/documents${query}`),
        api<SharedDocumentItem[]>('/documents/shared'),
      ])
      setDocuments(result)
      setSharedDocuments(shared)
      setError('')
    } catch (cause) {
      setError(
        cause instanceof Error
          ? `The change succeeded, but the list could not be refreshed: ${cause.message}`
          : 'The change succeeded, but the document list could not be refreshed.',
      )
    }
  }

  async function openSharing(item: DocumentItem) {
    setBusy(true)
    setError('')
    try {
      const result = await api<PermissionItem[]>(
        `/documents/${item.id}/permissions`,
      )
      setPermissions(result)
      setSharing(item.id)
      setShareEmail('')
      setShareCanDownload(false)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to load sharing settings.')
    } finally {
      setBusy(false)
    }
  }

  async function handleGrant(event: FormEvent<HTMLFormElement>, item: DocumentItem) {
    event.preventDefault()
    setBusy(true)
    setError('')
    setMessage('')
    try {
      const permission = await mutate<PermissionItem>(
        `/documents/${item.id}/permissions`,
        {
          method: 'POST',
          body: JSON.stringify({
            email: shareEmail,
            access_level: 'read',
            can_download: shareCanDownload,
          }),
        },
      )
      setPermissions((current) => [
        ...current.filter((entry) => entry.id !== permission.id),
        permission,
      ])
      setShareEmail('')
      setShareCanDownload(false)
      setMessage(`Access granted to ${permission.user_email}.`)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to share document.')
    } finally {
      setBusy(false)
    }
  }

  async function handleDownloadPermissionChange(
    item: DocumentItem,
    permission: PermissionItem,
    canDownload: boolean,
  ) {
    setBusy(true)
    setError('')
    setMessage('')
    try {
      const updated = await mutate<PermissionItem>(
        `/documents/${item.id}/permissions/${permission.id}`,
        {
          method: 'PATCH',
          body: JSON.stringify({ can_download: canDownload }),
        },
      )
      setPermissions((current) =>
        current.map((entry) => (entry.id === updated.id ? updated : entry)),
      )
      setMessage(
        `Download ${canDownload ? 'allowed' : 'disabled'} for ${permission.user_email}.`,
      )
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : 'Unable to update download permission.',
      )
    } finally {
      setBusy(false)
    }
  }

  async function handleRevoke(item: DocumentItem, permission: PermissionItem) {
    if (!window.confirm(`Revoke access for ${permission.user_email}?`)) return
    setBusy(true)
    setError('')
    setMessage('')
    try {
      await mutate<void>(
        `/documents/${item.id}/permissions/${permission.id}`,
        { method: 'DELETE' },
      )
      setPermissions((current) =>
        current.filter((entry) => entry.id !== permission.id),
      )
      setMessage(`Access revoked for ${permission.user_email}.`)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to revoke access.')
    } finally {
      setBusy(false)
    }
  }

  async function handleDownload(item: DocumentItem) {
    setBusy(true)
    setMessage('')
    setError('')
    try {
      const response = await apiResponse(`/documents/${item.id}/download`)
      const blob = await response.blob()
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = item.filename
      anchor.click()
      window.setTimeout(() => URL.revokeObjectURL(url), 1000)
      setMessage(`Downloaded ${item.name}.`)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to download document.')
    } finally {
      setBusy(false)
    }
  }

  function beginEdit(item: DocumentItem) {
    setEditing(item.id)
    setEditName(item.name)
    setEditCategory(item.category)
    setMessage('')
    setError('')
  }

  async function handleEdit(event: FormEvent<HTMLFormElement>, item: DocumentItem) {
    event.preventDefault()
    setBusy(true)
    setMessage('')
    setError('')
    try {
      await mutate<DocumentItem>(`/documents/${item.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ name: editName, category: editCategory }),
      })
      setEditing(null)
      setMessage('Document details updated.')
      await refreshDocuments()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to update document.')
    } finally {
      setBusy(false)
    }
  }

  async function handleDelete(item: DocumentItem) {
    if (!window.confirm(`Delete "${item.name}"? This cannot be undone.`)) return
    setBusy(true)
    setMessage('')
    setError('')
    try {
      await mutate<void>(`/documents/${item.id}`, { method: 'DELETE' })
      setMessage('Document deleted.')
      await refreshDocuments()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to delete document.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="mx-auto max-w-4xl px-4 py-10 sm:px-6">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-moss">
            Private workspace
          </p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight text-ink">
            Your documents
          </h1>
          <p className="mt-2 text-sm text-slate-600">
            Upload and manage your private files in one place.
          </p>
        </div>
        <label className="w-full sm:max-w-xs">
          <span className="sr-only">Search documents</span>
          <input
            className="w-full rounded-xl border border-slate-300 bg-white px-3 py-2.5 text-sm"
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search by document name"
            type="search"
            value={search}
          />
        </label>
      </div>

      <form
        className="mt-7 grid gap-3 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm sm:grid-cols-2"
        onSubmit={(event) => void handleUpload(event)}
      >
        <label className="text-sm font-medium text-ink sm:col-span-2">
          Upload a document
          <input
            accept=".pdf,.docx,.txt,.png,.jpg,.jpeg"
            className="mt-1.5 block w-full rounded-xl border border-slate-300 px-3 py-2 text-sm"
            id="document-upload"
            onChange={handleFileChange}
            required
            type="file"
          />
          <span className="mt-1 block text-xs font-normal text-slate-500">
            PDF, DOCX, TXT, PNG or JPG. Maximum size: 10 MB.
          </span>
        </label>
        <label className="text-sm font-medium text-ink">
          Display name (optional)
          <input
            className="mt-1.5 w-full rounded-xl border border-slate-300 px-3 py-2 text-sm"
            maxLength={160}
            onChange={(event) => setDisplayName(event.target.value)}
            placeholder={selectedFile?.name ?? 'Use the file name'}
            value={displayName}
          />
        </label>
        <label className="text-sm font-medium text-ink">
          Category
          <CategoryField
            id="upload-category"
            onChange={setCategory}
            options={categoryOptions}
            value={category}
          />
        </label>
        <button
          className="rounded-xl bg-ink px-4 py-2.5 text-sm font-semibold text-white hover:bg-moss disabled:opacity-60 sm:col-span-2 sm:justify-self-start"
          disabled={busy || !selectedFile}
          type="submit"
        >
          {busy ? 'Please wait…' : 'Upload document'}
        </button>
      </form>

      {message && (
        <p className="mt-5 rounded-xl bg-emerald-50 px-3 py-2 text-sm text-emerald-800" role="status">
          {message}
        </p>
      )}
      {error && (
        <p className="mt-5 rounded-xl bg-red-50 px-3 py-2 text-sm text-red-800" role="alert">
          {error}
        </p>
      )}

      <div className="mt-8">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-ink">Document library</h2>
          <span className="text-sm text-slate-500">
            {documents.length} {documents.length === 1 ? 'document' : 'documents'}
          </span>
        </div>
        {loading ? (
          <p className="rounded-2xl border border-slate-200 bg-white p-8 text-center text-sm text-slate-500">
            Loading your documents…
          </p>
        ) : documents.length === 0 ? (
          <p className="rounded-2xl border border-dashed border-slate-300 bg-white p-8 text-center text-sm text-slate-500">
            {search.trim()
              ? 'No documents match your search.'
              : 'No documents yet. Upload a file to get started.'}
          </p>
        ) : (
          <ul className="space-y-3">
            {documents.map((item) => (
              <li
                className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"
                key={item.id}
              >
                {editing === item.id ? (
                  <form
                    className="grid gap-3 sm:grid-cols-2"
                    onSubmit={(event) => void handleEdit(event, item)}
                  >
                    <label className="text-sm font-medium text-ink">
                      Display name
                      <input
                        className="mt-1 w-full rounded-xl border border-slate-300 px-3 py-2 text-sm"
                        maxLength={160}
                        onChange={(event) => setEditName(event.target.value)}
                        required
                        value={editName}
                      />
                    </label>
                    <label className="text-sm font-medium text-ink">
                      Category
                      <CategoryField
                        id={`edit-category-${item.id}`}
                        onChange={setEditCategory}
                        options={categoryOptions}
                        value={editCategory}
                      />
                    </label>
                    <div className="flex gap-2 sm:col-span-2">
                      <button
                        className="rounded-lg bg-ink px-3 py-2 text-sm font-semibold text-white disabled:opacity-60"
                        disabled={busy}
                        type="submit"
                      >
                        Save
                      </button>
                      <button
                        className="rounded-lg border border-slate-300 px-3 py-2 text-sm font-medium text-ink"
                        onClick={() => setEditing(null)}
                        type="button"
                      >
                        Cancel
                      </button>
                    </div>
                  </form>
                ) : (
                  <>
                    <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                      <div className="min-w-0 flex-1">
                        <h3 className="break-words font-semibold text-ink">
                          {item.name}
                        </h3>
                        <p className="mt-1 break-all text-xs text-slate-500">
                          {item.filename}
                        </p>
                        <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-2 text-xs text-slate-600 sm:grid-cols-4">
                          <div>
                            <dt className="text-slate-400">Type</dt>
                            <dd className="mt-0.5">{item.content_type}</dd>
                          </div>
                          <div>
                            <dt className="text-slate-400">Size</dt>
                            <dd className="mt-0.5">{formatSize(item.size_bytes)}</dd>
                          </div>
                          <div>
                            <dt className="text-slate-400">Uploaded</dt>
                            <dd className="mt-0.5">{formatDate(item.created_at)}</dd>
                          </div>
                          <div>
                            <dt className="text-slate-400">Owner</dt>
                            <dd className="mt-0.5 break-all">{item.owner_email}</dd>
                          </div>
                          <div>
                            <dt className="text-slate-400">Category</dt>
                            <dd className="mt-0.5">{item.category}</dd>
                          </div>
                        </dl>
                      </div>
                      <div className="flex shrink-0 flex-wrap gap-2" role="group" aria-label={`Actions for ${item.name}`}>
                        <DocumentActionButton
                          action="preview"
                          disabled={busy}
                          onClick={() => setPreviewing(item)}
                        />
                        <DocumentActionButton
                          action="download"
                          disabled={busy}
                          onClick={() => void handleDownload(item)}
                        />
                        <DocumentActionButton
                          action="edit"
                          disabled={busy}
                          onClick={() => beginEdit(item)}
                        />
                        <DocumentActionButton
                          action="share"
                          disabled={busy}
                          onClick={() => void openSharing(item)}
                        />
                        <DocumentActionButton
                          action="delete"
                          disabled={busy}
                          onClick={() => void handleDelete(item)}
                        />
                      </div>
                    </div>
                  </>
                )}
                {sharing === item.id && (
                  <div className="mt-5 border-t border-slate-200 pt-4">
                    <div className="mb-3 flex items-center justify-between">
                      <h4 className="font-medium text-ink">Document access</h4>
                      <button
                        className="text-sm text-slate-600 underline"
                        onClick={() => setSharing(null)}
                        type="button"
                      >
                        Close
                      </button>
                    </div>
                    <form
                      className="flex flex-col gap-2 sm:flex-row"
                      onSubmit={(event) => void handleGrant(event, item)}
                    >
                      <label className="sr-only" htmlFor={`share-email-${item.id}`}>
                        Registered user email
                      </label>
                      <input
                        className="min-w-0 flex-1 rounded-lg border border-slate-300 px-3 py-2 text-sm"
                        id={`share-email-${item.id}`}
                        onChange={(event) => setShareEmail(event.target.value)}
                        placeholder="Registered user email"
                        required
                        type="email"
                        value={shareEmail}
                      />
                      <label className="flex items-center gap-2 text-sm text-ink">
                        <input
                          checked={shareCanDownload}
                          className="h-4 w-4 accent-ink"
                          onChange={(event) =>
                            setShareCanDownload(event.target.checked)
                          }
                          type="checkbox"
                        />
                        Allow download
                      </label>
                      <button
                        className="rounded-lg bg-ink px-3 py-2 text-sm font-semibold text-white disabled:opacity-60"
                        disabled={busy}
                        type="submit"
                      >
                        Grant access
                      </button>
                    </form>
                    {permissions.length === 0 ? (
                      <p className="mt-3 text-sm text-slate-500">
                        This document has no active shares.
                      </p>
                    ) : (
                      <ul className="mt-3 divide-y divide-slate-100">
                        {permissions.map((permission) => (
                          <li
                            className="flex flex-wrap items-center justify-between gap-2 py-2 text-sm"
                            key={permission.id}
                          >
                            <div>
                              <span className="break-all text-ink">
                                {permission.user_email}
                                <span className="ml-2 text-slate-500">
                                  ({permission.access_level === 'read'
                                    ? 'Viewer'
                                    : 'Legacy edit grant — inactive'})
                                </span>
                              </span>
                              <p className="mt-1 text-xs text-slate-500">
                                Download{' '}
                                {permission.access_level === 'read' &&
                                permission.can_download
                                  ? 'allowed'
                                  : 'disabled'}
                              </p>
                            </div>
                            <div className="flex flex-wrap items-center gap-3">
                              {permission.access_level === 'read' && (
                                <label className="flex items-center gap-2 text-sm text-ink">
                                  <input
                                    checked={permission.can_download}
                                    className="h-4 w-4 accent-ink"
                                    disabled={busy}
                                    onChange={(event) =>
                                      void handleDownloadPermissionChange(
                                        item,
                                        permission,
                                        event.target.checked,
                                      )
                                    }
                                    type="checkbox"
                                  />
                                  Allow download
                                </label>
                              )}
                              <DocumentActionButton
                                action="revoke"
                                disabled={busy}
                                onClick={() => void handleRevoke(item, permission)}
                              />
                            </div>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="mt-10">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-ink">Shared with you</h2>
          <span className="text-sm text-slate-500">
            {sharedDocuments.filter((item) =>
              item.name.toLowerCase().includes(search.trim().toLowerCase()),
            ).length}{' '}
            documents
          </span>
        </div>
        {loading ? (
          <p className="rounded-2xl border border-slate-200 bg-white p-6 text-center text-sm text-slate-500">
            Loading shared documents…
          </p>
        ) : sharedDocuments.filter((item) =>
            item.name.toLowerCase().includes(search.trim().toLowerCase()),
          ).length === 0 ? (
          <p className="rounded-2xl border border-dashed border-slate-300 bg-white p-6 text-center text-sm text-slate-500">
            No documents have been shared with you.
          </p>
        ) : (
          <ul className="space-y-3">
            {sharedDocuments
              .filter((item) =>
                item.name.toLowerCase().includes(search.trim().toLowerCase()),
              )
              .map((item) => (
                <li
                  className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"
                  key={item.id}
                >
                  <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                    <div className="min-w-0 flex-1">
                      <h3 className="font-semibold text-ink">{item.name}</h3>
                      <p className="mt-1 text-xs text-slate-500">
                        Shared by {item.owner_email} · Viewer
                      </p>
                      <p className="mt-1 text-xs text-slate-500">
                        {item.content_type} · {formatSize(item.size_bytes)} ·{' '}
                        {formatDate(item.created_at)}
                      </p>
                    </div>
                    <div
                      aria-label={`Actions for ${item.name}`}
                      className="flex shrink-0 flex-wrap gap-2"
                      role="group"
                    >
                      <DocumentActionButton
                        action="preview"
                        onClick={() => setPreviewing(item)}
                      />
                      {item.can_download && (
                        <DocumentActionButton
                          action="download"
                          disabled={busy}
                          onClick={() => void handleDownload(item)}
                        />
                      )}
                    </div>
                  </div>
                </li>
              ))}
          </ul>
        )}
      </div>

      {previewing && (
        <div
          aria-labelledby="document-preview-title"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 p-4"
          role="dialog"
        >
          <div className="flex h-[90vh] w-full max-w-5xl flex-col rounded-2xl bg-white p-4 shadow-xl">
            <div className="mb-3 flex items-center justify-between gap-4">
              <h2
                className="truncate text-lg font-semibold text-ink"
                id="document-preview-title"
              >
                Preview: {previewing.name}
              </h2>
              <button
                className="rounded-lg border border-slate-300 px-3 py-2 text-sm font-medium text-ink"
                onClick={() => setPreviewing(null)}
                type="button"
              >
                Close preview
              </button>
            </div>
            {previewLoading ? (
              <p className="grid min-h-0 flex-1 place-items-center text-sm text-slate-500">
                Loading preview…
              </p>
            ) : previewError ? (
              <p
                className="grid min-h-0 flex-1 place-items-center rounded-lg bg-red-50 p-4 text-sm text-red-800"
                role="alert"
              >
                {previewError}
              </p>
            ) : previewing.content_type === 'application/pdf' && previewUrl ? (
              <iframe
                className="min-h-0 flex-1 rounded-lg border border-slate-200"
                src={previewUrl}
                title={`PDF preview of ${previewing.name}`}
              />
            ) : previewing.content_type.startsWith('image/') && previewUrl ? (
              <div className="grid min-h-0 flex-1 place-items-center overflow-auto rounded-lg border border-slate-200 bg-paper p-3">
                <img
                  alt={previewing.name}
                  className="max-h-full max-w-full object-contain"
                  src={previewUrl}
                />
              </div>
            ) : (
              <pre className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-slate-200 bg-paper p-4 text-sm text-ink">
                {previewText}
              </pre>
            )}
          </div>
        </div>
      )}
    </section>
  )
}

export default DocumentDashboard
