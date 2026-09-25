// JWT and password hashing, hand-rolled on node:crypto.
//
// Nothing here is hidden behind a library on purpose. Signing is done for you;
// `verifyAccessToken` below is a stub you have to implement. The rules it must
// enforce are in AUTH-DATA-MODEL.md §10 and restated in the TODO comment.
//
// The payload is base64, NOT encrypted. Never put a secret in it.

import { createHmac, timingSafeEqual, randomBytes, scryptSync, randomUUID } from 'node:crypto';
import { unauthenticated, tokenStale } from './http.js';
const ALG = 'HS256';
const ISS = 'remoteops';
const AUD = 'remoteops-api';

export const ACCESS_TTL_SECONDS = 15 * 60;
export const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;

const b64 = (buf) => Buffer.from(buf).toString('base64url');
const unb64 = (str) => Buffer.from(str, 'base64url');

export function signToken(claims, secret) {
  const header = { alg: ALG, typ: 'JWT' };
  const h = b64(JSON.stringify(header));
  const p = b64(JSON.stringify(claims));
  const sig = createHmac('sha256', secret).update(`${h}.${p}`).digest();
  return `${h}.${p}.${b64(sig)}`;
}

// Issue an access token. Note what is NOT in here: the resolved permission set.
// The token carries the authorization INPUTS (org, role, pv); the server resolves
// the permissions. See AUTH-DATA-MODEL.md §1 (D11).
export function issueAccessToken({ userId, orgId, role, permVersion }, secret) {
  const now = Math.floor(Date.now() / 1000);
  return signToken(
    {
      iss: ISS,
      aud: AUD,
      sub: userId,
      org: orgId,
      role,
      pv: permVersion,
      jti: randomUUID(),
      iat: now,
      exp: now + ACCESS_TTL_SECONDS,
    },
    secret
  );
}

// ---------------------------------------------------------------------------
// verifyAccessToken — AUTH-DATA-MODEL.md §10
//
// The algorithm is pinned BEFORE the header is trusted. This is the structural
// defence against alg:none and algorithm substitution: we never read the header's
// alg claim to decide which algorithm to verify with.
// ---------------------------------------------------------------------------
export function verifyAccessToken(token, secret) {
  // 1. Must be exactly three dot-separated segments
  if (typeof token !== 'string' || token === '') throw unauthenticated('malformed token');
  const parts = token.split('.');
  if (parts.length !== 3) throw unauthenticated('malformed token: expected 3 segments');

  const [rawHeader, rawPayload, rawSig] = parts;

  // 2. Decode and parse header — must be valid base64url JSON object
  let header;
  try {
    const decoded = JSON.parse(unb64(rawHeader).toString('utf8'));
    if (decoded === null || typeof decoded !== 'object' || Array.isArray(decoded)) {
      throw new Error('not an object');
    }
    header = decoded;
  } catch {
    throw unauthenticated('malformed token: invalid header');
  }

  // 3. Pin the algorithm — reject ANYTHING other than HS256/JWT.
  // Do NOT trust header.alg for the verification step; this rejects alg:none
  // and algorithm substitution structurally, not by denylist.
  if (header.alg !== ALG) throw unauthenticated('malformed token: unsupported algorithm');
  if (header.typ !== 'JWT') throw unauthenticated('malformed token: invalid typ');

  // 4. Verify signature in constant time using the pinned algorithm.
  // The signature is computed over "header.payload" (the raw base64url strings).
  let sigBuf;
  try {
    sigBuf = unb64(rawSig);
    if (sigBuf.length === 0) throw new Error('empty');
  } catch {
    throw unauthenticated('malformed token: invalid signature encoding');
  }

  const expected = createHmac('sha256', secret).update(`${rawHeader}.${rawPayload}`).digest();
  if (sigBuf.length !== expected.length || !timingSafeEqual(sigBuf, expected)) {
    throw unauthenticated('invalid token signature');
  }

  // 5. Decode and parse payload — must be valid base64url JSON object
  let claims;
  try {
    const decoded = JSON.parse(unb64(rawPayload).toString('utf8'));
    if (decoded === null || typeof decoded !== 'object' || Array.isArray(decoded)) {
      throw new Error('not an object');
    }
    claims = decoded;
  } catch {
    throw unauthenticated('malformed token: invalid payload');
  }

  // 6. Validate exp — must be a number, and must be strictly greater than now.
  // Half-open: exp == now is already expired (AUTH-DATA-MODEL.md D7).
  const nowSec = Math.floor(Date.now() / 1000);
  if (typeof claims.exp !== 'number' || claims.exp <= nowSec) {
    throw unauthenticated('token expired or missing exp');
  }

  // 7. Validate iss and aud
  if (claims.iss !== ISS) throw unauthenticated('invalid token issuer');
  if (claims.aud !== AUD) throw unauthenticated('invalid token audience');

  // 8. Validate jti — must be present and non-empty
  if (!claims.jti || typeof claims.jti !== 'string' || claims.jti.trim() === '') {
    throw unauthenticated('missing or empty jti');
  }

  return claims;
}


// The freshness check (AUTH-DATA-MODEL.md §3). Compares the token's pv against the
// membership's current perm_version. Note `!==`, not `<`: a token from the future is
// as suspect as a stale one.
export function assertFresh(claims, membership) {
  if (!membership) throw unauthenticated('not a member of this org');
  if (membership.perm_version !== claims.pv) throw tokenStale();
}

// --- opaque credentials: refresh tokens and invite tokens -------------------
//
// Both are bearer credentials that live in a database, so both are stored hashed —
// never plaintext, and never reversible. But they are DIFFERENT credentials, so they
// get DIFFERENT hash domains: sharing one would let a value from one table be compared
// against the other, which is a pointless and avoidable correlation.
//
// The key is an application secret, not a hardcoded literal. A hardcoded key means the
// hash is brute-forceable offline by anyone who reads this file — which defeats the
// point of hashing a high-entropy token.

export const newRefreshToken = () => randomBytes(32).toString('base64url');
export const newInviteToken  = () => randomBytes(32).toString('base64url');

const APP_HASH_KEY = process.env.APP_HASH_KEY ?? 'dev-only-app-hash-key-change-me';

export const hashRefreshToken = (raw) =>
  createHmac('sha256', `${APP_HASH_KEY}:refresh`).update(raw).digest('hex');

export const hashInviteToken = (raw) =>
  createHmac('sha256', `${APP_HASH_KEY}:invite`).update(raw).digest('hex');

// --- passwords --------------------------------------------------------------

export function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const derived = scryptSync(password, salt, 64).toString('hex');
  return `scrypt$${salt}$${derived}`;
}

export function verifyPassword(password, stored) {
  const [scheme, salt, expected] = String(stored ?? '').split('$');
  if (scheme !== 'scrypt' || !salt || !expected) return false;
  const actual = scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(actual, 'hex');
  const b = Buffer.from(expected, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}
