// ---------------------------------------------------------------------------
// Cluster-operator console auth. Two paths reach the API:
//
//   1. Break-glass mTLS client cert — when the operator's browser presents a
//      cluster admin cert, the API authenticates at the TLS layer and no bearer
//      is needed. /clusterconsole/v1/session then reports {auth:"cert"}.
//   2. OIDC browser login — the SPA runs Authorization Code + PKCE against the
//      IdP, obtains an id_token, and exchanges it ONCE at POST
//      /clusterconsole/auth/oidc for a controller-minted opaque CLUSTER session
//      token (Bearer, sessionStorage). The id_token is discarded after exchange.
//
// This mirrors the tenant console's flow but is a SEPARATE session namespace: a
// tenant session can never authenticate here and vice-versa.
// ---------------------------------------------------------------------------

const SESSION_KEY = "geneza-cluster-session"
const PKCE_KEY = "geneza-cluster-pkce-verifier"
const STATE_KEY = "geneza-cluster-oidc-state"
const DISCOVERY_KEY = "geneza-cluster-oidc-discovery"

export interface OidcConfig {
  issuer: string
  clientId: string
  redirectUri: string
}

export interface AuthConfig {
  clusterName: string
  oidc: OidcConfig | null
}

export interface Me {
  user: string
  auth: "cert" | "oidc"
  admin: boolean
  groups?: string[]
  expiresUnix?: number
}

interface DiscoveryDoc {
  authorization_endpoint: string
  token_endpoint: string
}

let inMemoryToken: string | null = sessionStorage.getItem(SESSION_KEY)

// --- base64url + PKCE helpers ----------------------------------------------

function base64UrlEncode(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let str = ""
  for (const b of arr) str += String.fromCharCode(b)
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

function randomString(byteLength = 32): string {
  const bytes = new Uint8Array(byteLength)
  crypto.getRandomValues(bytes)
  return base64UrlEncode(bytes)
}

async function sha256(input: string): Promise<ArrayBuffer> {
  return crypto.subtle.digest("SHA-256", new TextEncoder().encode(input))
}

// --- session token accessors ----------------------------------------------

export function getToken(): string | null {
  return inMemoryToken
}

function setToken(token: string | null) {
  inMemoryToken = token
  if (token) sessionStorage.setItem(SESSION_KEY, token)
  else sessionStorage.removeItem(SESSION_KEY)
}

export function hasSession(): boolean {
  return !!getToken()
}

export function clearSession() {
  setToken(null)
  sessionStorage.removeItem(PKCE_KEY)
  sessionStorage.removeItem(STATE_KEY)
}

// --- bootstrap config -------------------------------------------------------

export async function getAuthConfig(): Promise<AuthConfig> {
  const res = await fetch("/clusterconsole/auth/config", {
    credentials: "include",
    headers: { Accept: "application/json" },
  })
  if (!res.ok) throw new Error(`Failed to load auth config (${res.status})`)
  return (await res.json()) as AuthConfig
}

// --- the /me probe ----------------------------------------------------------

/** Resolve the current principal: a cluster session (bearer) or a break-glass
 * cert. Returns null when neither authenticates. */
export async function getMe(): Promise<Me | null> {
  const headers: Record<string, string> = { Accept: "application/json" }
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`
  const res = await fetch("/clusterconsole/v1/session", {
    credentials: "include",
    headers,
  })
  if (!res.ok) return null
  return (await res.json()) as Me
}

// --- OIDC discovery + Authorization Code + PKCE -----------------------------

async function discover(issuer: string): Promise<DiscoveryDoc> {
  const cached = sessionStorage.getItem(DISCOVERY_KEY)
  if (cached) {
    try {
      const parsed = JSON.parse(cached) as DiscoveryDoc & { _issuer?: string }
      if (parsed._issuer === issuer) return parsed
    } catch {
      /* ignore */
    }
  }
  const base = issuer.replace(/\/$/, "")
  const res = await fetch(`${base}/.well-known/openid-configuration`)
  if (!res.ok) throw new Error(`OIDC discovery failed (${res.status})`)
  const doc = (await res.json()) as DiscoveryDoc
  sessionStorage.setItem(DISCOVERY_KEY, JSON.stringify({ ...doc, _issuer: issuer }))
  return doc
}

function redirectUri(oidc: OidcConfig): string {
  // An empty redirectUri (no external_url configured) falls back to this origin.
  return oidc.redirectUri || `${window.location.origin}/`
}

export async function beginLogin(oidc: OidcConfig): Promise<void> {
  const disco = await discover(oidc.issuer)
  const verifier = randomString(32)
  const challenge = base64UrlEncode(await sha256(verifier))
  const state = randomString(16)
  sessionStorage.setItem(PKCE_KEY, verifier)
  sessionStorage.setItem(STATE_KEY, state)
  const params = new URLSearchParams({
    response_type: "code",
    client_id: oidc.clientId,
    redirect_uri: redirectUri(oidc),
    scope: "openid profile email",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  })
  window.location.assign(`${disco.authorization_endpoint}?${params.toString()}`)
}

export function hasAuthCallbackParams(): boolean {
  const params = new URLSearchParams(window.location.search)
  return params.has("code") || params.has("error")
}

interface CallbackResult {
  ok: boolean
  idToken?: string
  error?: string
}

/** Finish the IdP redirect: validate state, exchange the code (PKCE) for an
 * id_token, which is returned so it can be swapped for a cluster session. */
async function handleRedirectCallback(oidc: OidcConfig): Promise<CallbackResult> {
  const params = new URLSearchParams(window.location.search)
  const error = params.get("error")
  if (error) {
    clearTransient()
    return { ok: false, error: params.get("error_description") || error }
  }
  const code = params.get("code")
  const state = params.get("state")
  const expectedState = sessionStorage.getItem(STATE_KEY)
  const verifier = sessionStorage.getItem(PKCE_KEY)
  if (!code) return { ok: false, error: "Missing authorization code" }
  if (!state || state !== expectedState)
    return { ok: false, error: "State mismatch (possible CSRF)" }
  if (!verifier) return { ok: false, error: "Missing PKCE verifier" }

  const disco = await discover(oidc.issuer)
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri(oidc),
    client_id: oidc.clientId,
    code_verifier: verifier,
  })
  const res = await fetch(disco.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  })
  if (!res.ok) {
    clearTransient()
    let detail = `Token exchange failed (${res.status})`
    try {
      const j = await res.json()
      detail = j.error_description || j.error || detail
    } catch {
      /* ignore */
    }
    return { ok: false, error: detail }
  }
  const tokens = (await res.json()) as { id_token?: string }
  clearTransient()
  if (!tokens.id_token) return { ok: false, error: "No id_token in token response" }
  return { ok: true, idToken: tokens.id_token }
}

function clearTransient() {
  sessionStorage.removeItem(PKCE_KEY)
  sessionStorage.removeItem(STATE_KEY)
}

/** Swap a verified id_token for a controller cluster session (Bearer). */
async function exchangeOidc(idToken: string): Promise<void> {
  const res = await fetch("/clusterconsole/auth/oidc", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ idToken }),
  })
  if (!res.ok) {
    let detail = `Sign-in failed (${res.status})`
    try {
      const j = await res.json()
      if (j.error) detail = j.error
    } catch {
      /* ignore */
    }
    throw new Error(detail)
  }
  const data = (await res.json()) as { token?: string }
  if (!data.token) throw new Error("Unexpected sign-in response")
  setToken(data.token)
}

/** Complete a returned IdP redirect (code -> id_token -> cluster session). The
 * URL is cleaned afterwards. Returns an error string on failure, null on success. */
export async function completeLogin(oidc: OidcConfig): Promise<string | null> {
  const result = await handleRedirectCallback(oidc)
  window.history.replaceState({}, "", "/")
  if (!result.ok || !result.idToken) return result.error || "Sign-in failed"
  try {
    await exchangeOidc(result.idToken)
    return null
  } catch (e) {
    return (e as Error).message || "Sign-in failed"
  }
}

// --- logout -----------------------------------------------------------------

export async function logout(): Promise<void> {
  const token = getToken()
  if (token) {
    try {
      await fetch("/clusterconsole/v1/session", {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      })
    } catch {
      /* best effort */
    }
  }
  clearSession()
  sessionStorage.removeItem(DISCOVERY_KEY)
  window.location.assign("/")
}
