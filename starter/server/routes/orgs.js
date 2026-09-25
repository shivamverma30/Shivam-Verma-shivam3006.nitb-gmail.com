// Org, member, and audit routes.
//
// GET    /v1/orgs                               — list caller's orgs
// POST   /v1/orgs                               — create org (caller becomes owner)
// PATCH  /v1/orgs/:org                          — update org (org:update)
// DELETE /v1/orgs/:org                          — delete org (org:delete)
// GET    /v1/orgs/:org/members                  — list members (user:read)
// PATCH  /v1/orgs/:org/members/:userId          — change role (user:role:update)
// POST   /v1/orgs/:org/members/:userId/suspend  — suspend (user:remove)
// DELETE /v1/orgs/:org/members/:userId/suspend  — reinstate (user:remove)
// DELETE /v1/orgs/:org/members/:userId          — remove member (user:remove)
// DELETE /v1/orgs/:org/members/me               — self-leave
// GET    /v1/orgs/:org/users/:userId/effective  — effective permissions (user:read or self)
// GET    /v1/orgs/:org/audit                    — audit log (audit:read)

import { send, notFound, forbidden, badRequest, conflict, selfRoleChange } from '../http.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { assertCan } from '../permissions.js';
import { resolve } from '../permissions.js';
import { audit } from '../audit.js';
import {
  assertRoleExists,
  assertCanModify,
  assertCanAssignRole,
  assertNotLastOwner,
  endActiveSessions,
} from '../lifecycle.js';
import { issueAccessToken } from '../auth.js';

// Verify the org path param belongs to the caller's org (structural isolation).
// Returns the org row, or throws 404.
function requireOrgAccess(db, ctx, orgId) {
  if (orgId !== ctx.orgId) throw notFound('org not found');
  const org = db.prepare('SELECT id, name, theme, max_session_minutes FROM organizations WHERE id = ? AND deleted_at IS NULL').get(orgId);
  if (!org) throw notFound('org not found');
  return org;
}

export function registerOrgRoutes(router, { db, secret }) {
  // GET /v1/orgs — list orgs the caller belongs to
  router.get('/v1/orgs', async (ctx, _params, res) => {
    const orgs = db.prepare(`
      SELECT o.id, o.name, o.theme, m.role
      FROM organizations o
      JOIN memberships m ON m.org_id = o.id
      WHERE m.user_id = ? AND m.status != 'removed' AND o.deleted_at IS NULL
      ORDER BY o.name
    `).all(ctx.userId);
    send(res, 200, { orgs });
  });

  // POST /v1/orgs — create a new org, caller becomes the owner
  router.post('/v1/orgs', async (ctx, _params, res) => {
    const { name } = ctx.body;
    if (!name || typeof name !== 'string' || !name.trim()) {
      throw badRequest('org name is required');
    }
    if (name.trim().length > 100) throw badRequest('org name too long');

    // Determine theme: cycle through available themes deterministically
    const themes = ['cobalt', 'amber', 'moss', 'plum', 'rust', 'teal'];
    const orgCount = db.prepare('SELECT count(*) AS n FROM organizations WHERE deleted_at IS NULL').get().n;
    const theme = themes[orgCount % themes.length];

    const orgId = newId('org');
    const now = nowIso();

    const create = db.transaction(() => {
      db.prepare('INSERT INTO organizations (id, name, theme, max_session_minutes) VALUES (?,?,?,?)').run(orgId, name.trim(), theme, 60);

      // Find the highest-rank role (owner equivalent) from the database
      const ownerRole = db.prepare('SELECT key FROM roles ORDER BY rank DESC LIMIT 1').get();
      if (!ownerRole) throw new Error('no roles defined');

      const memId = newId('mem');
      db.prepare(
        'INSERT INTO memberships (id, org_id, user_id, role, status, joined_at) VALUES (?,?,?,?,?,?)'
      ).run(memId, orgId, ctx.userId, ownerRole.key, 'active', now);

      audit(db, {
        orgId,
        actorId: ctx.userId,
        action: 'org.create',
        targetType: 'org',
        targetId: orgId,
        result: 'allow',
        requestId: ctx.requestId,
      });
    });
    create();

    // Build response with the new org token
    const membership = db.prepare('SELECT role, perm_version FROM memberships WHERE org_id = ? AND user_id = ?').get(orgId, ctx.userId);
    const token = issueAccessToken({ userId: ctx.userId, orgId, role: membership.role, permVersion: membership.perm_version }, secret);
    const org = db.prepare('SELECT id, name, theme FROM organizations WHERE id = ?').get(orgId);

    send(res, 201, { id: orgId, name: org.name, theme: org.theme, role: membership.role, token });
  });

  // PATCH /v1/orgs/:org — rename/update org
  router.patch('/v1/orgs/:org', async (ctx, params, res) => {
    const org = requireOrgAccess(db, ctx, params.org);
    assertCan(db, ctx, 'org:update');

    const { name } = ctx.body;
    if (!name || typeof name !== 'string' || !name.trim()) throw badRequest('name is required');
    if (name.trim().length > 100) throw badRequest('name too long');

    const update = db.transaction(() => {
      db.prepare('UPDATE organizations SET name = ? WHERE id = ?').run(name.trim(), org.id);
      audit(db, { orgId: org.id, actorId: ctx.userId, action: 'org.update', targetType: 'org', targetId: org.id, result: 'allow', requestId: ctx.requestId });
    });
    update();
    const updated = db.prepare('SELECT id, name, theme FROM organizations WHERE id = ?').get(org.id);
    send(res, 200, updated);
  });

  // DELETE /v1/orgs/:org — soft delete
  router.delete('/v1/orgs/:org', async (ctx, params, res) => {
    const org = requireOrgAccess(db, ctx, params.org);
    assertCan(db, ctx, 'org:delete');

    const del = db.transaction(() => {
      db.prepare('UPDATE organizations SET deleted_at = ? WHERE id = ?').run(nowIso(), org.id);
      audit(db, { orgId: org.id, actorId: ctx.userId, action: 'org.delete', targetType: 'org', targetId: org.id, result: 'allow', requestId: ctx.requestId });
    });
    del();
    send(res, 200, { id: org.id });
  });

  // GET /v1/orgs/:org/members
  router.get('/v1/orgs/:org/members', async (ctx, params, res) => {
    requireOrgAccess(db, ctx, params.org);
    assertCan(db, ctx, 'user:read');

    const members = db.prepare(`
      SELECT u.id, u.email, u.name, m.role, m.status, m.joined_at
      FROM memberships m
      JOIN users u ON u.id = m.user_id
      WHERE m.org_id = ? AND m.status != 'removed'
      ORDER BY m.joined_at, u.name
    `).all(params.org);

    send(res, 200, { members });
  });

  // PATCH /v1/orgs/:org/members/:userId — change role
  router.patch('/v1/orgs/:org/members/:userId', async (ctx, params, res) => {
    requireOrgAccess(db, ctx, params.org);
    assertCan(db, ctx, 'user:role:update');

    const { role } = ctx.body;
    if (!role) throw badRequest('role is required');

    // Self-role-change is always forbidden
    if (params.userId === ctx.userId) throw selfRoleChange();

    assertRoleExists(db, role);

    // Get the target membership
    const targetMem = db.prepare(
      `SELECT id, role, status FROM memberships WHERE org_id = ? AND user_id = ? AND status != 'removed'`
    ).get(params.org, params.userId);
    if (!targetMem) throw notFound('member not found');

    // Rank-based modification authority
    assertCanModify(db, ctx.role, targetMem.role);
    assertCanAssignRole(db, ctx.role, role);

    // Check if assigning a new role would remove the last top-rank member
    // (only matters if demoting the current top-rank user)
    const topRole = db.prepare('SELECT key FROM roles ORDER BY rank DESC LIMIT 1').get();
    if (targetMem.role === topRole?.key && role !== topRole?.key) {
      assertNotLastOwner(db, params.org, params.userId);
    }

    const update = db.transaction(() => {
      db.prepare('UPDATE memberships SET role = ?, perm_version = perm_version + 1 WHERE org_id = ? AND user_id = ?')
        .run(role, params.org, params.userId);
      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'member.role_change', targetType: 'user', targetId: params.userId, result: 'allow', requestId: ctx.requestId });
    });
    update();
    send(res, 200, { userId: params.userId, role });
  });

  // POST /v1/orgs/:org/members/:userId/suspend
  router.post('/v1/orgs/:org/members/:userId/suspend', async (ctx, params, res) => {
    requireOrgAccess(db, ctx, params.org);
    assertCan(db, ctx, 'user:remove');

    const targetMem = db.prepare(
      `SELECT id, role, status FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`
    ).get(params.org, params.userId);
    if (!targetMem) throw notFound('active member not found');

    assertCanModify(db, ctx.role, targetMem.role);

    const suspend = db.transaction(() => {
      db.prepare("UPDATE memberships SET status = 'suspended', perm_version = perm_version + 1 WHERE org_id = ? AND user_id = ?")
        .run(params.org, params.userId);
      // Suspension cascades to sessions (PERMISSIONS.md §7.2)
      endActiveSessions(db, { orgId: params.org, userId: params.userId, reason: 'user_suspended' });
      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'member.suspend', targetType: 'user', targetId: params.userId, result: 'allow', requestId: ctx.requestId });
    });
    suspend();
    send(res, 200, { userId: params.userId, status: 'suspended' });
  });

  // DELETE /v1/orgs/:org/members/:userId/suspend — reinstate
  router.delete('/v1/orgs/:org/members/:userId/suspend', async (ctx, params, res) => {
    requireOrgAccess(db, ctx, params.org);
    assertCan(db, ctx, 'user:remove');

    const targetMem = db.prepare(
      `SELECT id, role, status FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'suspended'`
    ).get(params.org, params.userId);
    if (!targetMem) throw notFound('suspended member not found');

    assertCanModify(db, ctx.role, targetMem.role);

    const reinstate = db.transaction(() => {
      db.prepare("UPDATE memberships SET status = 'active', perm_version = perm_version + 1 WHERE org_id = ? AND user_id = ?")
        .run(params.org, params.userId);
      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'member.reinstate', targetType: 'user', targetId: params.userId, result: 'allow', requestId: ctx.requestId });
    });
    reinstate();
    send(res, 200, { userId: params.userId, status: 'active' });
  });

  // DELETE /v1/orgs/:org/members/me — self-leave (must be registered BEFORE /:userId)
  router.delete('/v1/orgs/:org/members/me', async (ctx, params, res) => {
    requireOrgAccess(db, ctx, params.org);
    assertNotLastOwner(db, params.org, ctx.userId);

    const remove = db.transaction(() => {
      db.prepare("UPDATE memberships SET status = 'removed', perm_version = perm_version + 1 WHERE org_id = ? AND user_id = ?")
        .run(params.org, ctx.userId);
      endActiveSessions(db, { orgId: params.org, userId: ctx.userId, reason: 'membership_removed' });
      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'member.self_remove', targetType: 'user', targetId: ctx.userId, result: 'allow', requestId: ctx.requestId });
    });
    remove();
    send(res, 200, { userId: ctx.userId });
  });

  // DELETE /v1/orgs/:org/members/:userId — remove a member
  router.delete('/v1/orgs/:org/members/:userId', async (ctx, params, res) => {
    requireOrgAccess(db, ctx, params.org);
    assertCan(db, ctx, 'user:remove');

    const targetMem = db.prepare(
      `SELECT id, role, status FROM memberships WHERE org_id = ? AND user_id = ? AND status != 'removed'`
    ).get(params.org, params.userId);
    if (!targetMem) throw notFound('member not found');

    assertCanModify(db, ctx.role, targetMem.role);
    assertNotLastOwner(db, params.org, params.userId);

    const remove = db.transaction(() => {
      db.prepare("UPDATE memberships SET status = 'removed', perm_version = perm_version + 1 WHERE org_id = ? AND user_id = ?")
        .run(params.org, params.userId);
      endActiveSessions(db, { orgId: params.org, userId: params.userId, reason: 'membership_removed' });
      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'member.remove', targetType: 'user', targetId: params.userId, result: 'allow', requestId: ctx.requestId });
    });
    remove();
    send(res, 200, { userId: params.userId });
  });

  // GET /v1/orgs/:org/users/:userId/effective — effective permissions for a user
  router.get('/v1/orgs/:org/users/:userId/effective', async (ctx, params, res) => {
    requireOrgAccess(db, ctx, params.org);

    // Allowed if caller is the user, or has user:read
    if (params.userId !== ctx.userId) {
      assertCan(db, ctx, 'user:read');
    }

    // Verify the target user is a member
    const targetMem = db.prepare(
      `SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ? AND status != 'removed'`
    ).get(params.org, params.userId);
    if (!targetMem) throw notFound('member not found');

    const resolved = resolve(db, { userId: params.userId, orgId: params.org, deviceId: null });
    send(res, 200, { role: resolved.role, permissions: resolved.permissions });
  });

  // GET /v1/orgs/:org/audit
  router.get('/v1/orgs/:org/audit', async (ctx, params, res) => {
    requireOrgAccess(db, ctx, params.org);
    assertCan(db, ctx, 'audit:read');

    const limitStr = ctx.query.get('limit') ?? '50';
    const offsetStr = ctx.query.get('offset') ?? '0';
    const limit = parseInt(limitStr, 10);
    const offset = parseInt(offsetStr, 10);

    if (!Number.isInteger(limit) || limit < 1 || limit > 200) {
      throw badRequest('limit must be between 1 and 200');
    }
    if (!Number.isInteger(offset) || offset < 0) {
      throw badRequest('offset must be >= 0');
    }

    const events = db.prepare(`
      SELECT id, actor_id, action, target_type, target_id, result, reason_code, request_id, at
      FROM audit_events
      WHERE org_id = ?
      ORDER BY at DESC
      LIMIT ? OFFSET ?
    `).all(params.org, limit, offset);

    const total = db.prepare('SELECT count(*) AS n FROM audit_events WHERE org_id = ?').get(params.org).n;
    send(res, 200, { events, total, limit, offset });
  });
}
