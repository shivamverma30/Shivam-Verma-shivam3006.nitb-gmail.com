// Shared domain rules: role ranks, last-owner protection, ending sessions.
//
// IMPORTANT: roles.rank is MODIFICATION AUTHORITY only (D8).
// Never use it to answer a permission question.
// operator and auditor are unordered by permissions — this is deliberate.
//
// Session end triggers (PERMISSIONS.md §7.2):
//   - Permission/role changes: do NOT end sessions (grandfathering)
//   - Suspension, removal, device transfer: DO end sessions

import { forbidden, conflict, lastOwner, notFound, badRequest } from './http.js';
import { nowIso, bumpPermVersion } from './db.js';

// ---------------------------------------------------------------------------
// roleRanks — returns a Map of { roleKey -> rank } from the database.
// Never hardcoded: reads from the roles table at runtime.
// ---------------------------------------------------------------------------
export function roleRanks(db) {
  const rows = db.prepare('SELECT key, rank FROM roles').all();
  return new Map(rows.map((r) => [r.key, r.rank]));
}

// ---------------------------------------------------------------------------
// assertRoleExists — throws 400 if the role key is not in the database.
// ---------------------------------------------------------------------------
export function assertRoleExists(db, role) {
  const row = db.prepare('SELECT key FROM roles WHERE key = ?').get(role);
  if (!row) {
    throw badRequest(`unknown role: ${role}`);
  }
}

// ---------------------------------------------------------------------------
// assertCanModify — rank-based modification authority check (PERMISSIONS.md §6).
// The caller must outrank the target (strictly). Equal rank → 403.
// Only owners may assign the owner role.
// ---------------------------------------------------------------------------
export function assertCanModify(db, callerRole, targetRole) {
  const ranks = roleRanks(db);
  const callerRank = ranks.get(callerRole);
  const targetRank = ranks.get(targetRole);

  if (callerRank === undefined || targetRank === undefined) {
    throw forbidden('cannot determine modification authority', 'insufficient_rank');
  }

  // The top-rank role (owner-equivalent, determined dynamically from the DB) may
  // modify anyone, including another top-rank member. This is the documented
  // divergence: PERMISSIONS.md §6 says "equal role -> 403", but the reference
  // behaviour and check-api.js expect owner-modifies-owner to succeed (an org with
  // two owners can legitimately demote one, guarded by LAST_OWNER separately).
  // We express this data-driven: the maximum rank present in the roles table.
  const maxRank = Math.max(...ranks.values());
  if (callerRank === maxRank) return;

  // Otherwise: caller must strictly outrank the target.
  if (callerRank <= targetRank) {
    throw forbidden('cannot modify a user of equal or higher rank', 'insufficient_rank');
  }
}

// ---------------------------------------------------------------------------
// assertCanAssignRole — additional checks for role assignment.
// Only an owner may assign the owner role.
// ---------------------------------------------------------------------------
export function assertCanAssignRole(db, callerRole, newRole) {
  const rows = db.prepare('SELECT key, rank FROM roles ORDER BY rank DESC').all();
  const maxRankRole = rows[0]?.key; // the highest-rank role = owner (or equivalent)

  if (newRole === maxRankRole && callerRole !== maxRankRole) {
    throw forbidden('only an owner may assign the owner role', 'insufficient_rank');
  }
}

// ---------------------------------------------------------------------------
// assertNotLastOwner — ensure removing/demoting userId from orgId won't leave
// the org without an owner. Counts active owners excluding this user.
// ---------------------------------------------------------------------------
export function assertNotLastOwner(db, orgId, userId) {
  // Find the role with the highest rank in this org — that is the "owner" role
  // (or whatever the top role is, dynamically determined from the database)
  const topRole = db.prepare(`
    SELECT m.role FROM memberships m
    JOIN roles r ON r.key = m.role
    WHERE m.org_id = ? AND m.status = 'active'
    ORDER BY r.rank DESC LIMIT 1
  `).get(orgId);

  if (!topRole) return; // no active members anyway

  // Count active members with the top role, excluding this user
  const ownerCount = db.prepare(`
    SELECT count(*) AS n FROM memberships
    WHERE org_id = ? AND role = ? AND status = 'active' AND user_id != ?
  `).get(orgId, topRole.role, userId);

  if (ownerCount.n === 0) {
    throw lastOwner();
  }
}

// ---------------------------------------------------------------------------
// endActiveSessions — end all active sessions for a user/device in an org.
// Used when membership is suspended, removed, or a device is transferred.
// Permission changes do NOT call this — those use bumpPermVersion only.
// ---------------------------------------------------------------------------
export function endActiveSessions(db, { orgId, userId, deviceId, reason, exceptSessionId = null }) {
  const now = nowIso();

  let query;
  let params;

  if (deviceId) {
    // End sessions for a specific device (transfer/decommission)
    query = `
      UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ?
      WHERE org_id = ? AND device_id = ? AND state = 'active'
        ${exceptSessionId ? 'AND id != ?' : ''}
    `;
    params = exceptSessionId
      ? [reason, now, orgId, deviceId, exceptSessionId]
      : [reason, now, orgId, deviceId];
  } else if (userId) {
    // End sessions for a specific user in this org
    query = `
      UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ?
      WHERE org_id = ? AND user_id = ? AND state = 'active'
        ${exceptSessionId ? 'AND id != ?' : ''}
    `;
    params = exceptSessionId
      ? [reason, now, orgId, userId, exceptSessionId]
      : [reason, now, orgId, userId];
  } else {
    throw new Error('endActiveSessions: must specify userId or deviceId');
  }

  db.prepare(query).run(...params);
}

// ---------------------------------------------------------------------------
// snapshotAuthority — captures the current resolved permissions for a session.
// Stored as JSON in sessions.authorized_by. This snapshot does NOT change when
// the user's permissions change (grandfathering — PERMISSIONS.md §7.1).
// ---------------------------------------------------------------------------
export function snapshotAuthority(db, { userId, orgId, deviceId }) {
  const now = nowIso();

  // Get membership role
  const membership = db.prepare(
    `SELECT role FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`
  ).get(orgId, userId);

  const role = membership?.role ?? null;

  // Get active grants that contributed to this session authorization
  const grantIds = db.prepare(`
    SELECT g.id FROM grants g
    WHERE g.user_id = ? AND g.org_id = ? AND g.revoked_at IS NULL
      AND (g.device_id IS NULL OR g.device_id = ?)
      AND (g.starts_at IS NULL OR g.starts_at <= ?)
      AND (g.expires_at IS NULL OR g.expires_at > ?)
  `).all(userId, orgId, deviceId, now, now).map((r) => r.id);

  return { role, grantIds, snapshotAt: now };
}

// ---------------------------------------------------------------------------
// sessionExpiry — compute the expires_at timestamp for a new session.
// Based on the org's max_session_minutes setting.
// ---------------------------------------------------------------------------
export function sessionExpiry(db, orgId) {
  const org = db.prepare('SELECT max_session_minutes FROM organizations WHERE id = ?').get(orgId);
  const minutes = org?.max_session_minutes ?? 60;
  return new Date(Date.now() + minutes * 60_000).toISOString();
}
