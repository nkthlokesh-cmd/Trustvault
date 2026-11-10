const configuredApiBaseUrl = import.meta.env.VITE_API_BASE_URL?.trim()
let API_BASE_URL = ''

if (configuredApiBaseUrl) {
  let parsedApiUrl: URL
  try {
    parsedApiUrl = new URL(configuredApiBaseUrl)
  } catch {
    throw new Error(
      'VITE_API_BASE_URL must be an absolute HTTP(S) backend origin.',
    )
  }
  if (
    !['http:', 'https:'].includes(parsedApiUrl.protocol) ||
    parsedApiUrl.pathname !== '/' ||
    parsedApiUrl.search ||
    parsedApiUrl.hash ||
    parsedApiUrl.username ||
    parsedApiUrl.password
  ) {
    throw new Error(
      'VITE_API_BASE_URL must be an HTTP(S) origin without a path or credentials.',
    )
  }
  API_BASE_URL = parsedApiUrl.origin
}

export class ApiError extends Error {
  readonly status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function responseError(response: Response): Promise<ApiError> {
  const responseText = await response.text()
  let payload: unknown = null
  if (responseText) {
    try {
      payload = JSON.parse(responseText) as unknown
    } catch {
      payload = null
    }
  }
  const detail =
    typeof payload === 'object' &&
    payload !== null &&
    'detail' in payload &&
    typeof payload.detail === 'string'
      ? payload.detail
      : `Request failed (${response.status})`
  return new ApiError(detail, response.status)
}

function apiUrl(path: string): string {
  return `${API_BASE_URL}/api${path}`
}

export async function apiResponse(
  path: string,
  options: RequestInit = {},
): Promise<Response> {
  const headers = new Headers(options.headers)
  if (options.body && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json')
  }
  const response = await fetch(apiUrl(path), {
    ...options,
    headers,
    credentials: 'include',
  })
  if (!response.ok) throw await responseError(response)
  return response
}

export async function api<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const response = await apiResponse(path, options)
  if (response.status === 204) return undefined as T
  const responseText = await response.text()
  if (!responseText) return undefined as T
  return JSON.parse(responseText) as T
}

export async function csrfToken(): Promise<string> {
  const result = await api<{ csrf_token: string }>('/auth/csrf')
  return result.csrf_token
}

export async function mutate<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const token = await csrfToken()
  const headers = new Headers(options.headers)
  headers.set('X-CSRF-Token', token)
  return api<T>(path, { ...options, headers })
}
