const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1'
const TOKEN_STORAGE_KEY = 'sih106.access_token'

function getAccessToken() {
  return typeof sessionStorage === 'undefined'
    ? ''
    : sessionStorage.getItem(TOKEN_STORAGE_KEY) || ''
}

function authHeaders(headers = {}) {
  const token = getAccessToken()
  return token
    ? { ...headers, Authorization: `Bearer ${token}` }
    : headers
}

async function parseError(response) {
  const contentType = response.headers.get('content-type') || ''
  if (contentType.includes('application/json')) {
    const body = await response.json()
    if (typeof body.detail === 'string') {
      return body.detail
    }
    return JSON.stringify(body.detail || body)
  }
  return (await response.text()) || `Request failed: ${response.status}`
}

function networkErrorMessage(error) {
  if (error instanceof TypeError || error?.name === 'TypeError') {
    return 'Unable to reach the backend service. Make sure the FastAPI server is running on http://127.0.0.1:8000 and the frontend is pointed at the same API base.'
  }

  if (error instanceof Error && error.message) {
    return error.message
  }

  return 'A network error occurred while contacting the backend.'
}

async function request(path, options = {}) {
  const headers = authHeaders({ ...(options.headers || {}) })
  if (options.body && !(options.body instanceof FormData) && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json'
  }

  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers,
    })

    if (!response.ok) {
      throw new Error(await parseError(response))
    }

    const contentType = response.headers.get('content-type') || ''
    if (contentType.includes('application/json')) {
      return response.json()
    }

    return response.text()
  } catch (error) {
    throw new Error(networkErrorMessage(error))
  }
}

export const api = {
  health: () => request('/health'),
  login: (username, password) =>
    request('/auth/token', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
  listAnalyses: () => request('/analyses'),
  getAnalysis: (analysisId) => request(`/analyses/${encodeURIComponent(analysisId)}`),
  modelInfo: () => request('/model-info'),
  analyzeFile: (file) => {
    const body = new FormData()
    body.append('file', file)
    return request('/analyze', { method: 'POST', body })
  },
  analyzeRaw: (rawEml) =>
    request('/analyze', {
      method: 'POST',
      body: JSON.stringify({ raw_eml: rawEml }),
    }),
  downloadReport: async (analysisId, token = '') => {
    const headers = authHeaders()
    if (token) {
      headers.Authorization = `Bearer ${token}`
    }
    const response = await fetch(`${API_BASE_URL}/reports/${analysisId}`, { headers })
    if (!response.ok) {
      throw new Error(await parseError(response))
    }
    return response.blob()
  },
}

export function setAccessToken(token) {
  if (typeof sessionStorage !== 'undefined') {
    sessionStorage.setItem(TOKEN_STORAGE_KEY, token)
  }
}

export { API_BASE_URL }
