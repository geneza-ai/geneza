import type { OidcConfig } from "@/types"

// ---------------------------------------------------------------------------
// The browser carries a CONTROLLER-MINTED opaque session token (Bearer), NOT an
// upstream IdP token. Login flows obtain a credential (local password, an OIDC
// id_token via Authorization Code + PKCE, or a keystone password) and exchange
// it ONCE at POST /api/v1/session/{local,oidc,keystone}; the controller returns the
// session token, which is kept in sessionStorage and sent as Authorization:
// Bearer. The upstream id_token is discarded after the exchange.
// ---------------------------------------------------------------------------

const SESSION_KEY = "geneza-session"
const PKCE_KEY = "geneza-pkce-verifier"
const STATE_KEY = "geneza-oidc-state"
const POST_LOGIN_KEY = "geneza-post-login"
const DISCOVERY_KEY = "geneza-oidc-discovery"
const PENDING_OIDC_KEY = "geneza-pending-oidc" // stashed id_token while choosing a workspace

interface DiscoveryDoc {
  authorization_endpoint: string
  token_endpoint: string
  end_session_endpoint?: string
}

let inMemoryToken: string | null = sessionStorage.getItem(SESSION_KEY)

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

// --- session token accessors ----------------------------------------------

export function getToken(): string | null {
  return inMemoryToken
}

function setToken(token: string | null) {
  inMemoryToken = token
  if (token) sessionStorage.setItem(SESSION_KEY, token)
  else sessionStorage.removeItem(SESSION_KEY)
}

/** A session token is present (the server is the authority on validity). */
export function hasValidSession(): boolean {
  return !!getToken()
}

export function clearSession() {
  setToken(null)
  sessionStorage.removeItem(PKCE_KEY)
  sessionStorage.removeItem(STATE_KEY)
  sessionStorage.removeItem(PENDING_OIDC_KEY)
}

// --- the /session exchange (all providers funnel here) ---------------------

export interface ProjectRef {
  id: string
  name: string
}

/** A login succeeds, or the principal must first choose a workspace or (for
 * keystone, with several projects) a project. */
export type LoginResult =
  | { ok: true; user: string; workspace: string }
  | { ok: false; kind: "workspace"; workspaces: string[] }
  | { ok: false; kind: "project"; projects: ProjectRef[] }

interface SessionBody {
  token?: string
  user?: string
  workspace?: string
  availableWorkspaces?: string[]
  availableProjects?: ProjectRef[]
}

async function postSession(
  provider: "local" | "oidc" | "keystone",
  body: Record<string, unknown>
): Promise<LoginResult> {
  const res = await fetch(`/api/v1/session/${provider}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
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
  const data = (await res.json()) as SessionBody
  if (data.token) {
    setToken(data.token)
    return { ok: true, user: data.user || "", workspace: data.workspace || "" }
  }
  if (data.availableProjects && data.availableProjects.length > 0) {
    return { ok: false, kind: "project", projects: data.availableProjects }
  }
  if (data.availableWorkspaces && data.availableWorkspaces.length > 0) {
    return { ok: false, kind: "workspace", workspaces: data.availableWorkspaces }
  }
  throw new Error("Unexpected sign-in response")
}

/** Optional choices a picker re-submits after the first attempt. */
export interface LoginChoice {
  workspace?: string
  projectId?: string
}

export function loginLocal(
  username: string,
  password: string,
  choice: LoginChoice = {}
): Promise<LoginResult> {
  return postSession("local", { username, password, workspace: choice.workspace })
}

export function loginKeystone(
  cloud: string,
  username: string,
  password: string,
  choice: LoginChoice & { domain?: string } = {}
): Promise<LoginResult> {
  return postSession("keystone", {
    cloud,
    username,
    password,
    domain: choice.domain,
    projectId: choice.projectId,
    workspace: choice.workspace,
  })
}

export function exchangeOidc(idToken: string, choice: LoginChoice = {}): Promise<LoginResult> {
  return postSession("oidc", { idToken, workspace: choice.workspace })
}

// --- trusted-dashboard handoff (R4) ----------------------------------------

/** The single-use handoff code from a trusted-dashboard 303 (?handoff=). */
export function handoffCode(): string | null {
  return new URLSearchParams(window.location.search).get("handoff")
}

/** Swap a handoff code (+ its HttpOnly companion cookie) for the session. */
export async function exchangeHandoff(code: string): Promise<boolean> {
  const res = await fetch("/api/v1/session/handoff", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin", // sends the geneza_handoff cookie
    body: JSON.stringify({ code }),
  })
  if (!res.ok) return false
  const data = (await res.json()) as SessionBody
  if (data.token) {
    setToken(data.token)
    return true
  }
  return false
}

// --- OIDC discovery + Authorization Code + PKCE (to obtain an id_token) -----

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

export async function beginLogin(oidc: OidcConfig): Promise<void> {
  const disco = await discover(oidc.issuer)
  const verifier = randomString(32)
  const challenge = base64UrlEncode(await sha256(verifier))
  const state = randomString(16)
  sessionStorage.setItem(PKCE_KEY, verifier)
  sessionStorage.setItem(STATE_KEY, state)
  sessionStorage.setItem(POST_LOGIN_KEY, window.location.pathname + window.location.hash)
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

export function hasAuthCallbackParams(): boolean {
  const params = new URLSearchParams(window.location.search)
  return params.has("code") || params.has("error")
}

export interface CallbackResult {
  ok: boolean
  postLoginPath: string
  /** Raw id_token from the IdP, to be exchanged at /session/oidc. */
  idToken?: string
  error?: string
}

/** Finish the IdP redirect: validate state, exchange the code (PKCE) for an
 * id_token. The id_token is returned to the caller to swap for a controller
 * session — it is NOT stored as the bearer. */
export async function handleRedirectCallback(oidc: OidcConfig): Promise<CallbackResult> {
  const params = new URLSearchParams(window.location.search)
  const postLoginPath = sessionStorage.getItem(POST_LOGIN_KEY) || "/"

  const error = params.get("error")
  if (error) {
    clearTransient()
    return { ok: false, postLoginPath, error: params.get("error_description") || error }
  }
  const code = params.get("code")
  const state = params.get("state")
  const expectedState = sessionStorage.getItem(STATE_KEY)
  const verifier = sessionStorage.getItem(PKCE_KEY)
  if (!code) return { ok: false, postLoginPath, error: "Missing authorization code" }
  if (!state || state !== expectedState)
    return { ok: false, postLoginPath, error: "State mismatch (possible CSRF)" }
  if (!verifier) return { ok: false, postLoginPath, error: "Missing PKCE verifier" }

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
      detail = j.error_description || j.error || detail
    } catch {
      /* ignore */
    }
    return { ok: false, postLoginPath, error: detail }
  }
  const tokens = (await res.json()) as { id_token?: string }
  clearTransient()
  if (!tokens.id_token) return { ok: false, postLoginPath, error: "No id_token in token response" }
  return { ok: true, postLoginPath, idToken: tokens.id_token }
}

function clearTransient() {
  sessionStorage.removeItem(PKCE_KEY)
  sessionStorage.removeItem(STATE_KEY)
  sessionStorage.removeItem(POST_LOGIN_KEY)
}

// While the user picks a workspace, stash the verified id_token (transient) so
// the picker can re-exchange it without re-running the IdP round-trip.
export function stashPendingOidc(idToken: string) {
  sessionStorage.setItem(PENDING_OIDC_KEY, idToken)
}
export function pendingOidc(): string | null {
  return sessionStorage.getItem(PENDING_OIDC_KEY)
}
export function clearPendingOidc() {
  sessionStorage.removeItem(PENDING_OIDC_KEY)
}

// --- logout ----------------------------------------------------------------

export async function logout(): Promise<void> {
  const token = getToken()
  // Server-side revoke so the session token is dead immediately.
  if (token) {
    try {
      await fetch("/api/v1/session", {
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
