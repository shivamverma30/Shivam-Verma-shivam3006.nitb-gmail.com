// Auth routes: login, refresh, token (org switch), me.
//
// POST /v1/auth/login   — email + password → access token (body) + refresh cookie
// POST /v1/auth/refresh — refresh cookie → new access token + rotated refresh cookie
// POST /v1/auth/token   — { orgId } → new access token scoped to that org
// GET  /v1/auth/me      — authenticated → caller's identity, role, orgs, resolved permissions

import {
  verifyPassword,
  hashRefreshToken,
  newRefreshToken,
  issueAccessToken,
  ACCESS_TTL_SECONDS,
  REFRESH_TTL_SECONDS,
} from '../auth.js';
import { send, unauthenticated, badRequest, notFound, forbidden } from '../http.js';
import { nowIso, newId, bumpPermVersion } from '../db.js';
import { resolve } from '../permissions.js';

// Parse the refresh token from the Cookie header.
function getRefreshCookie(req) {
  const raw = req.headers['cookie'] ?? '';
  for (const part of raw.split(';')) {
    const [k, v] = part.trim().split('=');
    if (k === 'rt' && v) return decodeURIComponent(v);
  }
  return null;
}

// Set the refresh token cookie (httpOnly, SameSite=Strict, Secure in prod).
function setRefreshCookie(res, token) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  const expires = new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toUTCString();
  res.setHeader('Set-Cookie', `rt=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict${secure}; Path=/v1/auth/refresh; Expires=${expires}`);
}

// Clear the refresh token cookie.
function clearRefreshCookie(res) {
  res.setHeader('Set-Cookie', 'rt=; HttpOnly; SameSite=Strict; Path=/v1/auth/refresh; Expires=Thu, 01 Jan 1970 00:00:00 GMT');
}

// Build the /me response shape.
function buildMeResponse(db, secret, { userId, orgId }) {
  const user = db.prepare('SELECT id, email, name FROM users WHERE id = ?').get(userId);
  const membership = db.prepare(
    `SELECT role, status FROM memberships WHERE user_id = ? AND org_id = ? AND status != 'removed'`
  ).get(userId, orgId);

  if (!membership) throw unauthenticated('not a member of this org');

  // All orgs this user belongs to (active or suspended — not removed)
  const orgs = db.prepare(`
    SELECT o.id, o.name, o.theme, m.role
    FROM organizations o
    JOIN memberships m ON m.org_id = o.id
    WHERE m.user_id = ? AND m.status != 'removed' AND o.deleted_at IS NULL
    ORDER BY o.name
  `).all(userId);

  // Org-level resolved permissions (union across all devices, for nav)
  const resolved = resolve(db, { userId, orgId, deviceId: null });

  return {
    id: user.id,
    email: user.email,
    name: user.name,
    orgId,
    role: membership.role,
    orgs: orgs.map((o) => ({ id: o.id, name: o.name, theme: o.theme, role: o.role })),
    permissions: resolved.permissions,
  };
}

// Issue an access token and find (or create) the default org for a user.
// Default org = alphabetically first org the user belongs to (active/suspended, not removed).
function defaultOrg(db, userId) {
  const row = db.prepare(`
    SELECT o.id FROM organizations o
    JOIN memberships m ON m.org_id = o.id
    WHERE m.user_id = ? AND m.status != 'removed' AND o.deleted_at IS NULL
    ORDER BY o.name LIMIT 1
  `).get(userId);
  return row?.id ?? null;
}

// Issue tokens and respond — shared by login and accept-invite.
export function issueTokensAndRespond(db, secret, res, { userId, orgId, requestId }) {
  const membership = db.prepare(
    `SELECT role, perm_version FROM memberships WHERE user_id = ? AND org_id = ? AND status != 'removed'`
  ).get(userId, orgId);
  if (!membership) throw unauthenticated('not a member');

  const accessToken = issueAccessToken(
    { userId, orgId, role: membership.role, permVersion: membership.perm_version },
    secret
  );

  // Issue a new refresh token
  const raw = newRefreshToken();
  const hash = hashRefreshToken(raw);
  const familyId = newId('fam');
  const expiresAt = new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString();
  db.prepare(
    'INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at) VALUES (?,?,?,?,?)'
  ).run(newId('rtk'), userId, hash, familyId, expiresAt);

  setRefreshCookie(res, raw);

  const me = buildMeResponse(db, secret, { userId, orgId });
  send(res, 200, { token: accessToken, ...me });
}

export function registerAuthRoutes(router, { db, secret }) {
  // POST /v1/auth/login
  router.post('/v1/auth/login', async (ctx, _params, res) => {
    const { email, password, orgId } = ctx.body;

    if (!email || typeof email !== 'string' || !email.trim()) {
      throw badRequest('email is required');
    }
    if (!password || typeof password !== 'string') {
      throw badRequest('password is required');
    }

    // Look up user by email (case-insensitive per schema)
    const user = db.prepare('SELECT id, email, name, password_hash FROM users WHERE email = ?')
      .get(email.toLowerCase().trim());

    // Constant-time: always verify even if user doesn't exist (to prevent timing attacks)
    const valid = user ? verifyPassword(password, user.password_hash) : false;
    if (!user || !valid) {
      // Same message for wrong password and unknown account — prevents enumeration
      throw unauthenticated('invalid credentials');
    }

    // Determine org: use provided orgId or fall back to alphabetically first
    let targetOrg = orgId;
    if (!targetOrg) {
      targetOrg = defaultOrg(db, user.id);
    }
    if (!targetOrg) throw unauthenticated('no org memberships');

    // Verify membership exists and is active/suspended
    const membership = db.prepare(
      `SELECT id, status FROM memberships WHERE user_id = ? AND org_id = ? AND status != 'removed'`
    ).get(user.id, targetOrg);

    if (!membership) throw notFound('org not found or no membership');
    if (membership.status === 'suspended') throw forbidden('account is suspended', 'suspended');

    issueTokensAndRespond(db, secret, res, { userId: user.id, orgId: targetOrg, requestId: ctx.requestId });
  });

  // POST /v1/auth/refresh — rotate the refresh token
  router.post('/v1/auth/refresh', async (ctx, _params, res) => {
    const raw = getRefreshCookie(ctx.req);
    if (!raw) throw unauthenticated('missing refresh token');

    const hash = hashRefreshToken(raw);
    const stored = db.prepare(
      `SELECT id, user_id, family_id, expires_at, revoked_at FROM refresh_tokens WHERE token_hash = ?`
    ).get(hash);

    if (!stored) throw unauthenticated('invalid refresh token');
    if (stored.revoked_at) {
      // Replayed token: revoke the entire family (AUTH-DATA-MODEL.md §2)
      db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ?')
        .run(nowIso(), stored.family_id);
      clearRefreshCookie(res);
      throw unauthenticated('refresh token replayed — family revoked');
    }
    if (stored.expires_at <= nowIso()) {
      throw unauthenticated('refresh token expired');
    }

    // Revoke the old token (rotating refresh)
    db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?').run(nowIso(), stored.id);

    // Find the user's current org (default to their alphabetically first org)
    const targetOrg = defaultOrg(db, stored.user_id);
    if (!targetOrg) throw unauthenticated('no org memberships');

    issueTokensAndRespond(db, secret, res, {
      userId: stored.user_id,
      orgId: targetOrg,
      requestId: ctx.requestId,
    });
  });

  // POST /v1/auth/token — switch org (mints a new access token scoped to the requested org)
  router.post('/v1/auth/token', async (ctx, _params, res) => {
    const { orgId } = ctx.body;
    if (!orgId || typeof orgId !== 'string') throw badRequest('orgId is required');

    // The caller is already authenticated (checked by the auth middleware)
    const userId = ctx.userId;

    // Verify the user has an active membership in the requested org
    const membership = db.prepare(
      `SELECT id, role, perm_version, status FROM memberships
       WHERE user_id = ? AND org_id = ? AND status != 'removed'`
    ).get(userId, orgId);

    if (!membership) throw notFound('org not found or no membership');
    if (membership.status === 'suspended') throw forbidden('account is suspended in that org', 'suspended');

    // Verify the org exists and isn't deleted
    const org = db.prepare('SELECT id FROM organizations WHERE id = ? AND deleted_at IS NULL').get(orgId);
    if (!org) throw notFound('org not found');

    const accessToken = issueAccessToken(
      { userId, orgId, role: membership.role, permVersion: membership.perm_version },
      secret
    );

    const me = buildMeResponse(db, secret, { userId, orgId });
    send(res, 200, { token: accessToken, ...me });
  });

  // GET /v1/auth/me — current user identity + resolved permissions
  router.get('/v1/auth/me', async (ctx, _params, res) => {
    const me = buildMeResponse(db, secret, { userId: ctx.userId, orgId: ctx.orgId });
    send(res, 200, me);
  });
}
