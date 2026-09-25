// The permission resolution engine. THE ONLY PLACE allow-vs-deny is decided.
//
// Algorithm (PERMISSIONS.md §3, D1–D10):
//   1. Identity: suspended → empty set (reason: suspended). Not a member → empty set (reason: not_a_member).
//   2. Collect grants applicable to this question (user, org, device scope, active window).
//   3. Deny wins (D1): any deny for this permission → deny with explicit_deny provenance.
//   4. Allow if the role baseline contains the permission OR any allow grant covers it.
//   5. Implicit deny: no source, reason 'implicit'.
//
// Wildcards: a grant naming 'device:*' is treated as granting/denying all device:X permissions.
// '*' covers all permissions. Resolution expands against the live permissions table (never hardcoded).
//
// The database is read dynamically. The overlay may add roles, permissions, and grants that
// don't appear in the reference docs. The engine never mentions a role or permission by name.

import { forbidden } from './http.js';

// ---------------------------------------------------------------------------
// Internal: load the full permission catalogue from the database.
// Returns an array of permission key strings.
// ---------------------------------------------------------------------------
function loadCatalogue(db) {
  return db.prepare('SELECT key FROM permissions ORDER BY key').all().map((r) => r.key);
}

// ---------------------------------------------------------------------------
// Internal: expand a set of permission patterns against the full catalogue.
// 'device:*' -> all 'device:X' keys; '*' -> all keys; 'device:control' -> ['device:control'].
// ---------------------------------------------------------------------------
function expandPatterns(patterns, catalogue) {
  const out = new Set();
  for (const pat of patterns) {
    if (pat === '*') {
      for (const k of catalogue) out.add(k);
    } else if (pat.endsWith(':*')) {
      const prefix = pat.slice(0, -1); // 'device:' 
      for (const k of catalogue) {
        if (k.startsWith(prefix)) out.add(k);
      }
    } else {
      // exact permission — only add if it's in the catalogue
      if (catalogue.includes(pat)) out.add(pat);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Internal: fetch all active (non-revoked, in-window) grants for a user in an org,
// optionally filtered to a device scope.
// Returns grants with their permissions already fetched.
// ---------------------------------------------------------------------------
function fetchActiveGrants(db, { userId, orgId, deviceId, now }) {
  const nowIso = now.toISOString();

  // Applicable grants: for the user in the org, not revoked, active window.
  // Device scope: a grant applies to this question if:
  //   - it is org-wide (device_id IS NULL), OR
  //   - it is scoped to this specific device (device_id = deviceId)
  // When deviceId is null (org-level view), we fetch ALL grants for the user in the org.
  let query;
  let params;

  if (deviceId === null) {
    // Org-level: all grants for this user/org (both org-wide and device-scoped).
    // The org-level union includes device-scoped grants too (for nav card logic).
    query = `
      SELECT g.id, g.device_id, g.effect
      FROM grants g
      WHERE g.user_id = ? AND g.org_id = ? AND g.revoked_at IS NULL
        AND (g.starts_at IS NULL OR g.starts_at <= ?)
        AND (g.expires_at IS NULL OR g.expires_at > ?)
    `;
    params = [userId, orgId, nowIso, nowIso];
  } else {
    // Device-level: org-wide grants AND this specific device's grants.
    query = `
      SELECT g.id, g.device_id, g.effect
      FROM grants g
      WHERE g.user_id = ? AND g.org_id = ? AND g.revoked_at IS NULL
        AND (g.device_id IS NULL OR g.device_id = ?)
        AND (g.starts_at IS NULL OR g.starts_at <= ?)
        AND (g.expires_at IS NULL OR g.expires_at > ?)
    `;
    params = [userId, orgId, deviceId, nowIso, nowIso];
  }

  const grantRows = db.prepare(query).all(...params);

  // Attach permissions to each grant
  const gpStmt = db.prepare('SELECT permission FROM grant_permissions WHERE grant_id = ?');
  return grantRows.map((g) => ({
    id: g.id,
    deviceId: g.device_id,
    effect: g.effect,
    permissions: gpStmt.all(g.id).map((r) => r.permission),
  }));
}

// ---------------------------------------------------------------------------
// Internal: get the role baseline permissions for a given role key.
// Reads from the database — never hardcoded.
// ---------------------------------------------------------------------------
function getRolePermissions(db, roleKey) {
  if (!roleKey) return new Set();
  return new Set(
    db.prepare('SELECT permission FROM role_permissions WHERE role = ?')
      .all(roleKey)
      .map((r) => r.permission)
  );
}

// ---------------------------------------------------------------------------
// Internal: resolve a single permission for a user in an org/device context.
// Returns { effect, source, reason }.
//
// Algorithm (PERMISSIONS.md §3):
//   D1: any applicable deny wins immediately (explicit_deny)
//   D3: grants are a delta in both directions
//   D4: absent means denied (implicit)
// ---------------------------------------------------------------------------
function resolveOne(permission, { grants, catalogue, roleBaseline, membershipStatus }) {
  // Identity check: suspended user has no permissions
  if (membershipStatus === 'suspended') {
    return { effect: 'deny', source: null, reason: 'suspended' };
  }

  // Expand grants into which permissions they apply to
  // D1: check ALL grants for a deny first — regardless of scope or specificity
  for (const grant of grants) {
    const covered = expandPatterns(grant.permissions, catalogue);
    if (covered.has(permission) && grant.effect === 'deny') {
      return { effect: 'deny', source: `grant:${grant.id}`, reason: 'explicit_deny' };
    }
  }

  // Check role baseline
  if (roleBaseline.has(permission)) {
    return { effect: 'allow', source: `role:${roleBaseline._roleKey}`, reason: null };
  }

  // Check allow grants
  for (const grant of grants) {
    const covered = expandPatterns(grant.permissions, catalogue);
    if (covered.has(permission) && grant.effect === 'allow') {
      return { effect: 'allow', source: `grant:${grant.id}`, reason: null };
    }
  }

  // D4: implicit deny
  return { effect: 'deny', source: null, reason: 'implicit' };
}

// ---------------------------------------------------------------------------
// Resolve one user's full permission set in one org.
// deviceId === null means the org-level view (union across all devices for nav).
// Returns { role, permissions: { [key]: { effect, source, reason } } }
// ---------------------------------------------------------------------------
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  // 1. Load membership
  const membership = db.prepare(
    `SELECT role, status, perm_version FROM memberships
     WHERE org_id = ? AND user_id = ? AND status != 'removed'`
  ).get(orgId, userId);

  if (!membership) {
    // Not a member: all permissions denied as 'not_a_member'
    const catalogue = loadCatalogue(db);
    const permissions = {};
    for (const key of catalogue) {
      permissions[key] = { effect: 'deny', source: null, reason: 'not_a_member' };
    }
    return { role: null, permissions };
  }

  const catalogue = loadCatalogue(db);
  const grants = fetchActiveGrants(db, { userId, orgId, deviceId, now });
  const roleBaseline = getRolePermissions(db, membership.role);
  roleBaseline._roleKey = membership.role; // attach for source string

  const permissions = {};
  for (const key of catalogue) {
    permissions[key] = resolveOne(key, {
      grants,
      catalogue,
      roleBaseline,
      membershipStatus: membership.status,
    });
  }

  return { role: membership.role, permissions };
}

// ---------------------------------------------------------------------------
// Batched form for device list endpoints.
// Returns { role, byDevice: { [deviceId]: permissions } }
// One membership lookup + one grant fetch per user, not per device.
// ---------------------------------------------------------------------------
export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  if (deviceIds.length === 0) return { role: null, byDevice: {} };

  const membership = db.prepare(
    `SELECT role, status, perm_version FROM memberships
     WHERE org_id = ? AND user_id = ? AND status != 'removed'`
  ).get(orgId, userId);

  if (!membership) {
    const catalogue = loadCatalogue(db);
    const emptyPerms = {};
    for (const key of catalogue) emptyPerms[key] = { effect: 'deny', source: null, reason: 'not_a_member' };
    const byDevice = {};
    for (const did of deviceIds) byDevice[did] = emptyPerms;
    return { role: null, byDevice };
  }

  const catalogue = loadCatalogue(db);
  const roleBaseline = getRolePermissions(db, membership.role);
  roleBaseline._roleKey = membership.role;
  const nowIso = now.toISOString();

  // Fetch ALL grants for this user/org in one query, covering all devices
  const allGrants = db.prepare(`
    SELECT g.id, g.device_id, g.effect
    FROM grants g
    WHERE g.user_id = ? AND g.org_id = ? AND g.revoked_at IS NULL
      AND (g.starts_at IS NULL OR g.starts_at <= ?)
      AND (g.expires_at IS NULL OR g.expires_at > ?)
  `).all(userId, orgId, nowIso, nowIso);

  const gpStmt = db.prepare('SELECT permission FROM grant_permissions WHERE grant_id = ?');
  const grantsWithPerms = allGrants.map((g) => ({
    id: g.id,
    deviceId: g.device_id,
    effect: g.effect,
    permissions: gpStmt.all(g.id).map((r) => r.permission),
  }));

  const orgWideGrants = grantsWithPerms.filter((g) => g.deviceId === null);

  const byDevice = {};
  for (const deviceId of deviceIds) {
    const deviceGrants = grantsWithPerms.filter((g) => g.deviceId === deviceId);
    const applicableGrants = [...orgWideGrants, ...deviceGrants];

    const permissions = {};
    for (const key of catalogue) {
      permissions[key] = resolveOne(key, {
        grants: applicableGrants,
        catalogue,
        roleBaseline,
        membershipStatus: membership.status,
      });
    }
    byDevice[deviceId] = permissions;
  }

  return { role: membership.role, byDevice };
}

// ---------------------------------------------------------------------------
// can — returns true/false without throwing.
// ---------------------------------------------------------------------------
export function can(db, ctx, permission, deviceId = null) {
  const result = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
  return result.permissions[permission]?.effect === 'allow';
}

// ---------------------------------------------------------------------------
// assertCan — throws 403 with the reason if denied.
// ---------------------------------------------------------------------------
export function assertCan(db, ctx, permission, deviceId = null) {
  const result = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
  const perm = result.permissions[permission];
  if (!perm || perm.effect !== 'allow') {
    const reason = perm?.reason ?? 'implicit';
    throw forbidden(`missing permission: ${permission}`, reason === 'explicit_deny' ? 'explicit_deny' : 'missing_permission');
  }
}

// ---------------------------------------------------------------------------
// assertMayGrant — no privilege laundering (D9).
// Caller must hold every permission being granted, at the requested scope.
// ---------------------------------------------------------------------------
export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  const catalogue = loadCatalogue(db);
  const expanded = expandPatterns(patterns, catalogue);

  for (const permission of expanded) {
    const result = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
    const perm = result.permissions[permission];
    if (!perm || perm.effect !== 'allow') {
      throw forbidden(
        `cannot grant ${permission}: you do not hold it at this scope`,
        'missing_permission'
      );
    }
  }
}

// ---------------------------------------------------------------------------
// assertCanStartSession — compound check: session:start AND the mode permission.
// Failure must distinguish which of the two was missing (PERMISSIONS.md §9).
// ---------------------------------------------------------------------------
export const MODE_PERMISSION = {
  view: 'device:view',
  control: 'device:control',
  terminal: 'device:terminal',
};

export function assertCanStartSession(db, ctx, mode, deviceId) {
  const modePerm = MODE_PERMISSION[mode];
  if (!modePerm) throw forbidden(`unknown session mode: ${mode}`);

  // Check session:start first — if missing, that's the primary failure
  const result = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });

  const startPerm = result.permissions['session:start'];
  if (!startPerm || startPerm.effect !== 'allow') {
    // 'missing_permission' = the caller cannot start sessions at all on this device
    throw Object.assign(
      forbidden('missing permission: session:start', 'missing_permission'),
      { reason: 'missing_permission' }
    );
  }

  const deviceModePerm = result.permissions[modePerm];
  if (!deviceModePerm || deviceModePerm.effect !== 'allow') {
    // 'missing_device_permission' = can start sessions but not in this mode on this device
    throw Object.assign(
      forbidden(`missing permission: ${modePerm}`, 'missing_device_permission'),
      { reason: 'missing_device_permission' }
    );
  }
}
