// API client for the RemoteOps console.
//
// The access token lives ONLY in memory (a module-level variable held by the caller
// via setToken). The refresh token is an httpOnly cookie the browser sends automatically
// on /v1/auth/refresh. Nothing is written to localStorage or sessionStorage.
//
// Every response error is surfaced with the server's { code, message, reason } so the
// UI can explain what went wrong rather than swallowing it.

let accessToken = null;

export function setToken(token) {
  accessToken = token;
}

export function getToken() {
  return accessToken;
}

export function clearToken() {
  accessToken = null;
}

// A structured error carrying the server's response detail.
export class ApiError extends Error {
  constructor(status, code, message, reason) {
    super(message || code || 'request failed');
    this.status = status;
    this.code = code;
    this.reason = reason;
  }
}

async function request(method, path, { body, auth = true } = {}) {
  const headers = {};
  if (auth && accessToken) headers['authorization'] = `Bearer ${accessToken}`;
  if (body !== undefined) headers['content-type'] = 'application/json';

  let res;
  try {
    res = await fetch(`/v1${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      credentials: 'same-origin', // send the refresh cookie where applicable
    });
  } catch (networkErr) {
    // The backend isn't answering — surface a readable reason, not a silent failure.
    throw new ApiError(0, 'NETWORK', 'the server is not responding', 'network_error');
  }

  const text = await res.text();
  let json = null;
  if (text) {
    try { json = JSON.parse(text); } catch { /* non-JSON body */ }
  }

  if (!res.ok) {
    const err = json?.error ?? {};
    throw new ApiError(res.status, err.code ?? 'ERROR', err.message ?? 'request failed', err.reason ?? null);
  }

  return json;
}

// --- auth -------------------------------------------------------------------

export const login = (email, password, orgId) =>
  request('POST', '/auth/login', { body: { email, password, ...(orgId ? { orgId } : {}) }, auth: false });

export const refresh = () =>
  request('POST', '/auth/refresh', { body: {}, auth: false });

export const switchOrg = (orgId) =>
  request('POST', '/auth/token', { body: { orgId } });

export const me = () => request('GET', '/auth/me');

// --- orgs -------------------------------------------------------------------

export const listOrgs = () => request('GET', '/orgs');
export const createOrg = (name) => request('POST', '/orgs', { body: { name } });
export const renameOrg = (orgId, name) => request('PATCH', `/orgs/${orgId}`, { body: { name } });
export const deleteOrg = (orgId) => request('DELETE', `/orgs/${orgId}`);

// --- members ----------------------------------------------------------------

export const listMembers = (orgId) => request('GET', `/orgs/${orgId}/members`);
export const changeRole = (orgId, userId, role) => request('PATCH', `/orgs/${orgId}/members/${userId}`, { body: { role } });
export const suspendMember = (orgId, userId) => request('POST', `/orgs/${orgId}/members/${userId}/suspend`, { body: {} });
export const reinstateMember = (orgId, userId) => request('DELETE', `/orgs/${orgId}/members/${userId}/suspend`);
export const removeMember = (orgId, userId) => request('DELETE', `/orgs/${orgId}/members/${userId}`);
export const leaveOrg = (orgId) => request('DELETE', `/orgs/${orgId}/members/me`);

// --- invites ----------------------------------------------------------------

export const createInvite = (orgId, email, role) => request('POST', `/orgs/${orgId}/invites`, { body: { email, role } });
export const listInvites = (orgId) => request('GET', `/orgs/${orgId}/invites`);
export const cancelInvite = (orgId, id) => request('DELETE', `/orgs/${orgId}/invites/${id}`);
export const peekInvite = (token) => request('GET', `/invites/${token}`, { auth: false });
export const acceptInvite = (token, name, password) => request('POST', `/invites/${token}/accept`, { body: { name, password }, auth: false });

// --- devices ----------------------------------------------------------------

export const listDevices = (orgId) => request('GET', `/orgs/${orgId}/devices`);
export const getDevice = (orgId, id) => request('GET', `/orgs/${orgId}/devices/${id}`);
export const provisionDevice = (orgId, name, kind) => request('POST', `/orgs/${orgId}/devices`, { body: { name, kind } });
export const renameDevice = (orgId, id, name) => request('PATCH', `/orgs/${orgId}/devices/${id}`, { body: { name } });
export const decommissionDevice = (orgId, id) => request('DELETE', `/orgs/${orgId}/devices/${id}`);

// --- grants -----------------------------------------------------------------

export const listGrants = (orgId) => request('GET', `/orgs/${orgId}/grants`);
export const createGrant = (orgId, grant) => request('POST', `/orgs/${orgId}/grants`, { body: grant });
export const revokeGrant = (orgId, id) => request('DELETE', `/orgs/${orgId}/grants/${id}`);

// --- sessions ---------------------------------------------------------------

export const listSessions = (orgId) => request('GET', `/orgs/${orgId}/sessions`);
export const startSession = (orgId, deviceId, mode) => request('POST', `/orgs/${orgId}/sessions`, { body: { deviceId, mode } });
export const stopSession = (id) => request('DELETE', `/sessions/${id}`);

// --- audit ------------------------------------------------------------------

export const listAudit = (orgId, limit = 50, offset = 0) => request('GET', `/orgs/${orgId}/audit?limit=${limit}&offset=${offset}`);
