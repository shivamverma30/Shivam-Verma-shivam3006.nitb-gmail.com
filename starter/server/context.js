// Per-request context: turn a bearer token into an authenticated caller.
//
// Structural isolation guarantee (AUTH-DATA-MODEL.md §4):
//   The token's `org` claim is the ONLY org the caller may address.
//   A request to a different org returns 404, not 403 — the org is invisible.
//   This is enforced by the membership lookup: if there is no membership for
//   (userId, token.org), the caller has no context in that org.
//
// Freshness (AUTH-DATA-MODEL.md §3):
//   perm_version on the membership must equal the token's `pv` claim.
//   A role change, grant change, or suspension bumps perm_version, making the
//   existing token stale. The client must refresh to get a new token.

import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, forbidden, notFound } from './http.js';

// authenticate(db, secret) returns a middleware-style function that:
//   - reads the Authorization: Bearer <token> header
//   - verifies the token (signature, expiry, iss, aud, jti)
//   - looks up the membership for (sub, org) — the org comes from the TOKEN, not params
//   - checks freshness (perm_version)
//   - returns a ctx object: { userId, orgId, role, membership, claims, db, secret, ... }
//
// The returned function throws on any failure; callers should wrap in try/catch.

export function authenticate(db, secret) {
  return function buildContext(req, params) {
    // Extract the bearer token
    const authHeader = req.headers['authorization'] ?? '';
    if (!authHeader.startsWith('Bearer ')) {
      throw unauthenticated('missing or malformed Authorization header');
    }
    const token = authHeader.slice(7).trim();
    if (!token) throw unauthenticated('empty bearer token');

    // Verify the token (signature, exp, iss, aud, jti)
    // This throws unauthenticated() on any failure.
    const claims = verifyAccessToken(token, secret);

    // Look up the membership for (userId=sub, orgId=org from token)
    // IMPORTANT: the org comes from the TOKEN, not from the URL params.
    // A request with an Acme token to /orgs/org_globex/... will look up
    // the membership for (usr_dana, org_acme) — and since the path org doesn't
    // match, the route handler's own org check will return 404.
    const membership = db.prepare(
      `SELECT id, org_id, user_id, role, status, perm_version
       FROM memberships
       WHERE user_id = ? AND org_id = ?`
    ).get(claims.sub, claims.org);

    // If no membership exists for this (user, org) pair, the token is invalid
    if (!membership) {
      throw unauthenticated('not a member of this org');
    }

    // Removed members cannot authenticate
    if (membership.status === 'removed') {
      throw unauthenticated('membership has been removed');
    }

    // Check freshness: perm_version must match exactly (not just >=)
    // AUTH-DATA-MODEL.md §3: use !== not <; a future pv is equally suspect
    assertFresh(claims, membership);

    // Suspended members: their token is valid and fresh, but they have
    // an empty permission set. The request proceeds; permission checks will fail.
    // (Suspended is not unauthenticated; it is a specific authorization state.)

    return {
      userId: claims.sub,
      orgId: claims.org,
      role: membership.role,
      membership,
      claims,
    };
  };
}
