import { useCallback, useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'

import AdminDashboard from './AdminDashboard'
import DocumentDashboard from './DocumentDashboard'
import { ApiError, api, csrfToken, mutate } from './api'

type User = {
  id: string
  email: string
  display_name: string
  is_admin: boolean
  created_at: string
  status?: string | null
}

function App() {
  const [user, setUser] = useState<User | null>(null)
  const [profileOpen, setProfileOpen] = useState(false)
  const [loading, setLoading] = useState(true)
  const [registerMode, setRegisterMode] = useState(false)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [email, setEmail] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [passwordVisible, setPasswordVisible] = useState(false)
  const [workspace, setWorkspace] = useState<'documents' | 'admin'>('documents')
  const profileRef = useRef<HTMLDivElement>(null)
  const profileButtonRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    let active = true
    void (async () => {
      try {
        await csrfToken()
        const currentUser = await api<User>('/auth/me')
        if (active) setUser(currentUser)
      } catch (error) {
        if (!(error instanceof ApiError && error.status === 401) && active) {
          setMessage(
            error instanceof Error
              ? error.message
              : 'Unable to connect to the TrustVault API.',
          )
        }
      } finally {
        if (active) setLoading(false)
      }
    })()
    return () => {
      active = false
    }
  }, [])

  useEffect(() => {
    if (!profileOpen) return

    function handlePointerDown(event: PointerEvent) {
      if (
        event.target instanceof Node &&
        !profileRef.current?.contains(event.target)
      ) {
        setProfileOpen(false)
      }
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setProfileOpen(false)
        profileButtonRef.current?.focus()
      }
    }

    document.addEventListener('pointerdown', handlePointerDown)
    document.addEventListener('keydown', handleKeyDown)
    return () => {
      document.removeEventListener('pointerdown', handlePointerDown)
      document.removeEventListener('keydown', handleKeyDown)
    }
  }, [profileOpen])

  async function handleAuthentication(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    setMessage('')
    try {
      if (registerMode) {
        await mutate('/auth/register', {
          method: 'POST',
          body: JSON.stringify({ email, password, display_name: displayName }),
        })
      }
      const signedIn = await mutate<User>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      })
      await csrfToken()
      setUser(signedIn)
      setWorkspace('documents')
      setPassword('')
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to sign in.')
    } finally {
      setBusy(false)
    }
  }

  async function handleLogout() {
    setProfileOpen(false)
    setMessage('')
    try {
      await mutate('/auth/logout', { method: 'POST' })
      setUser(null)
      setRegisterMode(false)
      setEmail('')
      setDisplayName('')
      setPassword('')
      setPasswordVisible(false)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Unable to sign out.')
      profileButtonRef.current?.focus()
    }
  }

  const handleAdminSessionInvalid = useCallback(() => {
    setUser(null)
    setWorkspace('documents')
    setMessage(
      'Your session or Admin access is no longer valid. Please sign in again.',
    )
  }, [])

  if (loading) {
    return (
      <main className="grid min-h-screen place-items-center text-sm text-moss">
        Loading TrustVault…
      </main>
    )
  }

  if (!user) {
    return (
      <main className="flex min-h-screen items-center justify-center px-4 py-10">
        <section className="w-full max-w-md rounded-3xl border border-slate-200 bg-white p-8 shadow-sm">
          <div className="mb-8">
            <div className="mb-5 grid h-12 w-12 place-items-center rounded-2xl bg-ink text-xl text-white">
              T
            </div>
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-moss">
              Private document workspace
            </p>
            <h1 className="mt-2 text-3xl font-semibold tracking-tight text-ink">
              {registerMode ? 'Create your account' : 'Welcome to TrustVault'}
            </h1>
            <p className="mt-2 text-sm leading-6 text-slate-600">
              Sign in to your account or register to get started.
            </p>
          </div>
          <form className="space-y-4" onSubmit={handleAuthentication}>
            {registerMode && (
              <label className="block text-sm font-medium text-ink">
                Display name
                <input
                  autoComplete="name"
                  className="mt-1.5 w-full rounded-xl border border-slate-300 px-3 py-2.5 text-sm"
                  maxLength={120}
                  onChange={(event) => setDisplayName(event.target.value)}
                  placeholder="Your name"
                  value={displayName}
                />
              </label>
            )}
            <label className="block text-sm font-medium text-ink">
              Email
              <input
                autoComplete="email"
                className="mt-1.5 w-full rounded-xl border border-slate-300 px-3 py-2.5 text-sm"
                onChange={(event) => setEmail(event.target.value)}
                required
                type="email"
                value={email}
              />
            </label>
            <label className="block text-sm font-medium text-ink">
              Password
              <div className="relative mt-1.5">
                <input
                  autoComplete={registerMode ? 'new-password' : 'current-password'}
                  className="w-full rounded-xl border border-slate-300 px-3 py-2.5 pr-11 text-sm"
                  minLength={12}
                  maxLength={128}
                  onChange={(event) => setPassword(event.target.value)}
                  required
                  type={passwordVisible ? 'text' : 'password'}
                  value={password}
                />
                <button
                  aria-label={passwordVisible ? 'Hide password' : 'Show password'}
                  className="absolute inset-y-0 right-0 grid w-11 place-items-center rounded-r-xl text-slate-500 hover:text-ink"
                  onClick={() => setPasswordVisible((visible) => !visible)}
                  type="button"
                >
                  {passwordVisible ? (
                    <svg aria-hidden="true" className="h-5 w-5" fill="none" viewBox="0 0 24 24">
                      <path d="M3 3l18 18M10.6 10.6a2 2 0 002.8 2.8" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" />
                      <path d="M9.9 5.2A10.8 10.8 0 0112 5c5.2 0 8.5 5.1 8.5 7s-1.1 3.1-2.8 4.7M6.2 6.2C3.9 7.7 2.5 10.2 2.5 12c0 1.9 3.3 7 9.5 7 1.2 0 2.3-.2 3.3-.6" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" />
                    </svg>
                  ) : (
                    <svg aria-hidden="true" className="h-5 w-5" fill="none" viewBox="0 0 24 24">
                      <path d="M2.5 12s3.3-7 9.5-7 9.5 7 9.5 7-3.3 7-9.5 7-9.5-7-9.5-7z" stroke="currentColor" strokeLinejoin="round" strokeWidth="1.8" />
                      <circle cx="12" cy="12" r="3" stroke="currentColor" strokeWidth="1.8" />
                    </svg>
                  )}
                </button>
              </div>
              {registerMode && (
                <span className="mt-1 block text-xs font-normal text-slate-500">
                  Use at least 12 characters.
                </span>
              )}
            </label>
            {message && (
              <p
                className="rounded-xl bg-red-50 px-3 py-2 text-sm text-red-800"
                role="alert"
              >
                {message}
              </p>
            )}
            <button
              className="w-full rounded-xl bg-ink px-4 py-3 text-sm font-semibold text-white hover:bg-moss disabled:opacity-60"
              disabled={busy}
              type="submit"
            >
              {busy ? 'Please wait…' : registerMode ? 'Create account' : 'Sign in'}
            </button>
          </form>
          <button
            className="mt-5 w-full text-sm font-medium text-moss hover:text-ink"
            onClick={() => {
              setRegisterMode((current) => !current)
              setEmail('')
              setDisplayName('')
              setPassword('')
              setPasswordVisible(false)
              setMessage('')
            }}
            type="button"
          >
            {registerMode
              ? 'Already registered? Sign in'
              : 'New to TrustVault? Create an account'}
          </button>
        </section>
      </main>
    )
  }

  return (
    <main className="min-h-screen">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-4 py-4 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-xl bg-ink font-semibold text-white">
              T
            </div>
            <div>
              <p className="font-semibold leading-5 text-ink">TrustVault</p>
              <p className="text-xs text-slate-500">Private document workspace</p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {user.is_admin && (
              <nav aria-label="Workspace navigation" className="flex gap-2">
                <button
                  aria-current={workspace === 'documents' ? 'page' : undefined}
                  className={`rounded-lg px-3 py-2 text-sm font-medium ${
                    workspace === 'documents'
                      ? 'bg-ink text-white'
                      : 'border border-slate-300 text-ink hover:bg-paper'
                  }`}
                  onClick={() => setWorkspace('documents')}
                  type="button"
                >
                  Documents
                </button>
                <button
                  aria-current={workspace === 'admin' ? 'page' : undefined}
                  className={`rounded-lg px-3 py-2 text-sm font-medium ${
                    workspace === 'admin'
                      ? 'bg-ink text-white'
                      : 'border border-slate-300 text-ink hover:bg-paper'
                  }`}
                  onClick={() => setWorkspace('admin')}
                  type="button"
                >
                  Admin
                </button>
              </nav>
            )}
            <div className="relative" ref={profileRef}>
              <button
                aria-controls={profileOpen ? 'profile-panel' : undefined}
                aria-expanded={profileOpen}
                aria-label="Profile and account details"
                className="grid h-10 w-10 place-items-center rounded-full border border-slate-300 bg-white text-ink hover:bg-paper"
                onClick={() => setProfileOpen((open) => !open)}
                ref={profileButtonRef}
                type="button"
              >
                <svg aria-hidden="true" className="h-5 w-5" fill="none" viewBox="0 0 24 24">
                  <circle cx="12" cy="8" r="3.5" stroke="currentColor" strokeWidth="1.7" />
                  <path d="M5 20a7 7 0 0114 0" stroke="currentColor" strokeLinecap="round" strokeWidth="1.7" />
                </svg>
              </button>
              {profileOpen && (
                <section
                  aria-label="Account details"
                  className="absolute right-0 z-30 mt-2 w-[min(20rem,calc(100vw-2rem))] rounded-2xl border border-slate-200 bg-white p-4 shadow-lg"
                  id="profile-panel"
                >
                  <div className="border-b border-slate-100 pb-3">
                    {user.display_name && user.display_name !== user.email && (
                      <p className="font-semibold text-ink">{user.display_name}</p>
                    )}
                    <p className="break-all text-sm text-slate-600">{user.email}</p>
                  </div>
                  <dl className="space-y-2 py-3 text-sm">
                    <div className="flex justify-between gap-4">
                      <dt className="text-slate-500">Role</dt>
                      <dd className="font-medium text-ink">
                        {user.is_admin ? 'Admin' : 'User'}
                      </dd>
                    </div>
                    {user.status && (
                      <div className="flex justify-between gap-4">
                        <dt className="text-slate-500">Account status</dt>
                        <dd className="font-medium capitalize text-ink">
                          {user.status}
                        </dd>
                      </div>
                    )}
                  </dl>
                  <button
                    className="w-full rounded-lg border border-slate-300 px-3 py-2 text-left text-sm font-medium text-ink hover:bg-paper"
                    onClick={() => void handleLogout()}
                    type="button"
                  >
                    Sign out
                  </button>
                </section>
              )}
            </div>
          </div>
        </div>
      </header>
      {message && (
        <p
          className="mx-auto mt-5 max-w-4xl rounded-xl bg-red-50 px-3 py-2 text-sm text-red-800"
          role="alert"
        >
          {message}
        </p>
      )}
      {workspace === 'admin' && user.is_admin ? (
        <AdminDashboard
          currentUserId={user.id}
          onSessionExpired={handleAdminSessionInvalid}
        />
      ) : (
        <DocumentDashboard />
      )}
    </main>
  )
}

export default App
