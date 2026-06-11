import type { OidcConfig } from "@/types"

// ---------------------------------------------------------------------------
// OIDC Authorization Code + PKCE (public client, no secret), implemented in
// the browser. Tokens are kept in memory and mirrored to sessionStorage so a
// full-page redirect (the auth round-trip) survives without persisting beyond
// the tab session.
// ---------------------------------------------------------------------------

const TOKEN_KEY = "geneza-id-token"
const PKCE_KEY = "geneza-pkce-verifier"
const STATE_KEY = "geneza-oidc-state"
const POST_LOGIN_KEY = "geneza-post-login"
const DISCOVERY_KEY = "geneza-oidc-discovery"

interface DiscoveryDoc {
  authorization_endpoint: string
  token_endpoint: string
  end_session_endpoint?: string
}

interface IdTokenClaims {
  sub?: string
  name?: string
  preferred_username?: string
  email?: string
  exp?: number
  iss?: string
  [key: string]: unknown
}

let inMemoryToken: string | null = sessionStorage.getItem(TOKEN_KEY)

// --- base64url helpers -----------------------------------------------------

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
  const data = new TextEncoder().encode(input)
  return crypto.subtle.digest("SHA-256", data)
}

// --- token accessors -------------------------------------------------------

export function getToken(): string | null {
  return inMemoryToken
}

function setToken(token: string | null) {
  inMemoryToken = token
  if (token) sessionStorage.setItem(TOKEN_KEY, token)
  else sessionStorage.removeItem(TOKEN_KEY)
}

export function decodeIdToken(token: string): IdTokenClaims | null {
  try {
    const payload = token.split(".")[1]
    if (!payload) return null
    const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"))
    return JSON.parse(decodeURIComponent(escape(json))) as IdTokenClaims
  } catch {
    return null
  }
}

/** A locally-valid token is present and not expired (clock-skew tolerant). */
export function hasValidSession(): boolean {
  const token = getToken()
  if (!token) return false
  const claims = decodeIdToken(token)
  if (!claims?.exp) return true // can't tell; let the server decide
  return claims.exp * 1000 > Date.now() + 5000
}

export function clearSession() {
  setToken(null)
  sessionStorage.removeItem(PKCE_KEY)
  sessionStorage.removeItem(STATE_KEY)
}

// --- discovery -------------------------------------------------------------

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
  if (!res.ok) {
    throw new Error(`OIDC discovery failed (${res.status})`)
  }
  const doc = (await res.json()) as DiscoveryDoc
  sessionStorage.setItem(
    DISCOVERY_KEY,
    JSON.stringify({ ...doc, _issuer: issuer })
  )
  return doc
}

// --- login redirect --------------------------------------------------------

export async function beginLogin(oidc: OidcConfig): Promise<void> {
  const disco = await discover(oidc.issuer)

  const verifier = randomString(32)
  const challenge = base64UrlEncode(await sha256(verifier))
  const state = randomString(16)

  sessionStorage.setItem(PKCE_KEY, verifier)
  sessionStorage.setItem(STATE_KEY, state)
  // Remember where the user was (minus any auth params) to restore after login.
  sessionStorage.setItem(
    POST_LOGIN_KEY,
    window.location.pathname + window.location.hash
  )

  const params = new URLSearchParams({
    response_type: "code",
    client_id: oidc.clientId,
    redirect_uri: oidc.redirectUri,
    scope: "openid profile email",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  })

  window.location.assign(`${disco.authorization_endpoint}?${params.toString()}`)
}

// --- redirect callback -----------------------------------------------------

export function hasAuthCallbackParams(): boolean {
  const params = new URLSearchParams(window.location.search)
  return params.has("code") || params.has("error")
}

export interface CallbackResult {
  ok: boolean
  postLoginPath: string
  error?: string
}

/**
 * Handle the redirect back from the IdP: validate state, exchange the code for
 * tokens at the token endpoint (PKCE, no secret), and store the id_token.
 */
export async function handleRedirectCallback(
  oidc: OidcConfig
): Promise<CallbackResult> {
  const params = new URLSearchParams(window.location.search)
  const postLoginPath = sessionStorage.getItem(POST_LOGIN_KEY) || "/"

  const error = params.get("error")
  if (error) {
    clearTransient()
    return {
      ok: false,
      postLoginPath,
      error: params.get("error_description") || error,
    }
  }

  const code = params.get("code")
  const state = params.get("state")
  const expectedState = sessionStorage.getItem(STATE_KEY)
  const verifier = sessionStorage.getItem(PKCE_KEY)

  if (!code) return { ok: false, postLoginPath, error: "Missing authorization code" }
  if (!state || state !== expectedState) {
    return { ok: false, postLoginPath, error: "State mismatch (possible CSRF)" }
  }
  if (!verifier) {
    return { ok: false, postLoginPath, error: "Missing PKCE verifier" }
  }

  const disco = await discover(oidc.issuer)

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: oidc.redirectUri,
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
      if (j.error_description) detail = j.error_description
      else if (j.error) detail = j.error
    } catch {
      /* ignore */
    }
    return { ok: false, postLoginPath, error: detail }
  }

  const tokens = (await res.json()) as { id_token?: string; access_token?: string }
  const idToken = tokens.id_token
  if (!idToken) {
    clearTransient()
    return { ok: false, postLoginPath, error: "No id_token in token response" }
  }

  setToken(idToken)
  clearTransient()
  return { ok: true, postLoginPath }
}

function clearTransient() {
  sessionStorage.removeItem(PKCE_KEY)
  sessionStorage.removeItem(STATE_KEY)
  sessionStorage.removeItem(POST_LOGIN_KEY)
}

// --- logout ----------------------------------------------------------------

export async function logout(oidc: OidcConfig): Promise<void> {
  const token = getToken()
  clearSession()
  sessionStorage.removeItem(DISCOVERY_KEY)
  try {
    const disco = await discover(oidc.issuer)
    if (disco.end_session_endpoint) {
      const params = new URLSearchParams({
        post_logout_redirect_uri: oidc.redirectUri,
        client_id: oidc.clientId,
      })
      if (token) params.set("id_token_hint", token)
      window.location.assign(
        `${disco.end_session_endpoint}?${params.toString()}`
      )
      return
    }
  } catch {
    /* fall through to local logout */
  }
  window.location.assign("/")
}
