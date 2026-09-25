// Device and grant routes.
//
// GET    /v1/orgs/:org/devices           — list devices (device:list) + per-device permissions
// GET    /v1/orgs/:org/devices/:id       — device detail (device:view)
// POST   /v1/orgs/:org/devices           — provision device (device:provision)
// PATCH  /v1/orgs/:org/devices/:id       — update device (device:update)
// DELETE /v1/orgs/:org/devices/:id       — decommission (device:provision)
// POST   /v1/orgs/:org/devices/:id/transfer — transfer to another org (device:provision in both)
// POST   /v1/orgs/:org/grants            — create grant (grant:create)
// GET    /v1/orgs/:org/grants            — list grants (user:read)
// DELETE /v1/orgs/:org/grants/:id        — revoke grant (grant:revoke)

import { send, notFound, forbidden, badRequest, conflict, normalizeTs, HttpError } from '../http.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { assertCan, assertMayGrant, resolve, resolveDevices } from '../permissions.js';
import { endActiveSessions } from '../lifecycle.js';
import { audit } from '../audit.js';

function requireOrgAccess(db, ctx, orgId) {
  if (orgId !== ctx.orgId) throw notFound('org not found');
  const org = db.prepare('SELECT id, name FROM organizations WHERE id = ? AND deleted_at IS NULL').get(orgId);
  if (!org) throw notFound('org not found');
  return org;
}

function requireDevice(db, orgId, deviceId) {
  const device = db.prepare(
    'SELECT id, org_id, name, kind, online FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL'
  ).get(deviceId, orgId);
  if (!device) throw notFound('device not found');
  return device;
}

export function registerDeviceRoutes(router, { db, secret }) {
  // GET /v1/orgs/:org/devices — list with per-device resolved permissions
  router.get('/v1/orgs/:org/devices', async (ctx, params, res) => {
    requireOrgAccess(db, ctx, params.org);
    assertCan(db, ctx, 'device:list');

    const allDevices = db.prepare(
      'SELECT id, name, kind, online FROM devices WHERE org_id = ? AND deleted_at IS NULL ORDER BY name'
    ).all(params.org);

    if (allDevices.length === 0) {
      send(res, 200, { devices: [] });
      return;
    }

    // Batch-resolve permissions for all devices in one pass (not N+1)
    const deviceIds = allDevices.map((d) => d.id);
    const { role, byDevice } = resolveDevices(db, { userId: ctx.userId, orgId: params.org, deviceIds });

    // Filter to only devices the caller can view (device:view), per PERMISSIONS.md §2
    const devices = allDevices
      .filter((d) => byDevice[d.id]?.['device:view']?.effect === 'allow')
      .map((d) => ({
        id: d.id,
        name: d.name,
        kind: d.kind,
        online: d.online === 1,
        permissions: byDevice[d.id],
      }));

    send(res, 200, { devices });
  });

  // GET /v1/orgs/:org/devices/:id
  router.get('/v1/orgs/:org/devices/:id', async (ctx, params, res) => {
    requireOrgAccess(db, ctx, params.org);
    assertCan(db, ctx, 'device:view', params.id);

    const device = requireDevice(db, params.org, params.id);
    const resolved = resolve(db, { userId: ctx.userId, orgId: params.org, deviceId: params.id });

    send(res, 200, {
      id: device.id,
      name: device.name,
      kind: device.kind,
      online: device.online === 1,
      permissions: resolved.permissions,
    });
  });

  // POST /v1/orgs/:org/devices — provision
  router.post('/v1/orgs/:org/devices', async (ctx, params, res) => {
    requireOrgAccess(db, ctx, params.org);
    assertCan(db, ctx, 'device:provision');

    const { name, kind } = ctx.body;
    if (!name || typeof name !== 'string' || !name.trim()) throw badRequest('name is required');
    const validKinds = ['macos', 'windows', 'linux', 'android', 'ios'];
    if (!validKinds.includes(kind)) throw badRequest(`kind must be one of: ${validKinds.join(', ')}`);

    const deviceId = newId('dev');
    const create = db.transaction(() => {
      db.prepare('INSERT INTO devices (id, org_id, name, kind, online) VALUES (?,?,?,?,0)')
        .run(deviceId, params.org, name.trim(), kind);
      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'device.provision', targetType: 'device', targetId: deviceId, result: 'allow', requestId: ctx.requestId });
    });
    create();

    const device = db.prepare('SELECT id, name, kind, online FROM devices WHERE id = ?').get(deviceId);
    send(res, 201, { ...device, online: device.online === 1 });
  });

  // PATCH /v1/orgs/:org/devices/:id — update name/kind
  router.patch('/v1/orgs/:org/devices/:id', async (ctx, params, res) => {
    requireOrgAccess(db, ctx, params.org);
    assertCan(db, ctx, 'device:update', params.id);
    const device = requireDevice(db, params.org, params.id);

    const updates = [];
    const vals = [];
    if (ctx.body.name !== undefined) {
      if (!ctx.body.name || !ctx.body.name.trim()) throw badRequest('name cannot be empty');
      updates.push('name = ?');
      vals.push(ctx.body.name.trim());
    }
    if (ctx.body.kind !== undefined) {
      const validKinds = ['macos', 'windows', 'linux', 'android', 'ios'];
      if (!validKinds.includes(ctx.body.kind)) throw badRequest('invalid kind');
      updates.push('kind = ?');
      vals.push(ctx.body.kind);
    }
    if (ctx.body.online !== undefined) {
      updates.push('online = ?');
      vals.push(ctx.body.online ? 1 : 0);
    }
    if (updates.length === 0) throw badRequest('no fields to update');

    const update = db.transaction(() => {
      db.prepare(`UPDATE devices SET ${updates.join(', ')} WHERE id = ?`).run(...vals, params.id);
      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'device.update', targetType: 'device', targetId: params.id, result: 'allow', requestId: ctx.requestId });
    });
    update();

    const updated = db.prepare('SELECT id, name, kind, online FROM devices WHERE id = ?').get(params.id);
    send(res, 200, { ...updated, online: updated.online === 1 });
  });

  // DELETE /v1/orgs/:org/devices/:id — decommission
  router.delete('/v1/orgs/:org/devices/:id', async (ctx, params, res) => {
    requireOrgAccess(db, ctx, params.org);
    assertCan(db, ctx, 'device:provision', params.id);
    requireDevice(db, params.org, params.id);

    const decommission = db.transaction(() => {
      db.prepare('UPDATE devices SET deleted_at = ? WHERE id = ?').run(nowIso(), params.id);
      endActiveSessions(db, { orgId: params.org, deviceId: params.id, reason: 'device_transferred' });
      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'device.decommission', targetType: 'device', targetId: params.id, result: 'allow', requestId: ctx.requestId });
    });
    decommission();
    send(res, 200, { id: params.id });
  });

  // POST /v1/orgs/:org/devices/:id/transfer — transfer device to another org
  // Requires device:provision in BOTH source and target orgs
  router.post('/v1/orgs/:org/devices/:id/transfer', async (ctx, params, res) => {
    requireOrgAccess(db, ctx, params.org);
    assertCan(db, ctx, 'device:provision', params.id);
    requireDevice(db, params.org, params.id);

    const { targetOrgId } = ctx.body;
    if (!targetOrgId) throw badRequest('targetOrgId is required');

    // Check device:provision in the target org — but structural isolation means
    // the token is for params.org. We check the membership directly.
    const targetMem = db.prepare(
      `SELECT m.role FROM memberships m WHERE m.user_id = ? AND m.org_id = ? AND m.status = 'active'`
    ).get(ctx.userId, targetOrgId);
    if (!targetMem) throw notFound('target org not found or no membership');

    // Resolve permissions in target org to check device:provision
    const targetResolved = resolve(db, { userId: ctx.userId, orgId: targetOrgId, deviceId: null });
    if (targetResolved.permissions['device:provision']?.effect !== 'allow') {
      throw forbidden('missing device:provision in target org', 'missing_permission');
    }

    const transfer = db.transaction(() => {
      endActiveSessions(db, { orgId: params.org, deviceId: params.id, reason: 'device_transferred' });
      db.prepare('UPDATE devices SET org_id = ? WHERE id = ?').run(targetOrgId, params.id);
      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'device.transfer', targetType: 'device', targetId: params.id, result: 'allow', requestId: ctx.requestId });
    });
    transfer();
    send(res, 200, { id: params.id, targetOrgId });
  });

  // POST /v1/orgs/:org/grants — create a grant
  router.post('/v1/orgs/:org/grants', async (ctx, params, res) => {
    requireOrgAccess(db, ctx, params.org);
    assertCan(db, ctx, 'grant:create');

    const { userId: targetUserId, deviceId, effect, permissions: permPatterns, startsAt, expiresAt } = ctx.body;

    if (!targetUserId) throw badRequest('userId is required');
    if (!effect || !['allow', 'deny'].includes(effect)) throw badRequest('effect must be allow or deny');
    if (!Array.isArray(permPatterns) || permPatterns.length === 0) {
      throw badRequest('permissions must be a non-empty array');
    }

    // Self-grant: forbidden (D9)
    if (targetUserId === ctx.userId) {
      throw forbidden('cannot create a grant for yourself', 'self_grant');
    }

    // Verify the target user is an active member
    const targetMem = db.prepare(
      `SELECT id FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`
    ).get(params.org, targetUserId);
    if (!targetMem) throw notFound('user is not an active member of this org');

    // Verify deviceId if specified
    if (deviceId) {
      const dev = db.prepare('SELECT id FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(deviceId, params.org);
      if (!dev) throw notFound('device not found in this org');
    }

    // Validate permission patterns against the catalogue (FK will reject unknown, but give a better error)
    for (const pat of permPatterns) {
      const exists = db.prepare('SELECT pattern FROM permission_patterns WHERE pattern = ?').get(pat);
      if (!exists) {
        throw badRequest(`unknown permission: ${pat}`, 'unknown_permission');
      }
    }

    // Validate timestamps
    const normalStarts = normalizeTs(startsAt ?? null, 'startsAt');
    const normalExpires = normalizeTs(expiresAt ?? null, 'expiresAt');
    if (normalExpires && normalExpires <= nowIso()) {
      throw new HttpError(400, 'GRANT_EXPIRED', 'expiresAt is in the past', 'expired_grant');
    }

    // No-laundering check (D9): caller must hold all permissions at the requested scope
    assertMayGrant(db, ctx, permPatterns, deviceId ?? null);

    const grantId = newId('grt');
    const create = db.transaction(() => {
      db.prepare(
        'INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by) VALUES (?,?,?,?,?,?,?,?)'
      ).run(grantId, params.org, targetUserId, deviceId ?? null, effect, normalStarts, normalExpires, ctx.userId);

      const gpStmt = db.prepare('INSERT INTO grant_permissions (grant_id, permission) VALUES (?,?)');
      for (const p of permPatterns) gpStmt.run(grantId, p);

      // Bump target's perm_version — next request will see the change
      bumpPermVersion(db, { orgId: params.org, userId: targetUserId });

      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'grant.create', targetType: 'grant', targetId: grantId, result: 'allow', requestId: ctx.requestId });
    });

    try {
      create();
    } catch (err) {
      // FK violation = unknown permission pattern
      if (err?.code === 'SQLITE_CONSTRAINT_FOREIGNKEY' || err?.message?.includes('FOREIGN KEY')) {
        throw badRequest('unknown permission in grant', 'unknown_permission');
      }
      throw err;
    }

    const grant = db.prepare('SELECT id, user_id, device_id, effect, starts_at, expires_at FROM grants WHERE id = ?').get(grantId);
    send(res, 201, { ...grant, permissions: permPatterns });
  });

  // GET /v1/orgs/:org/grants
  router.get('/v1/orgs/:org/grants', async (ctx, params, res) => {
    requireOrgAccess(db, ctx, params.org);
    assertCan(db, ctx, 'user:read');

    const grants = db.prepare(`
      SELECT g.id, g.user_id, g.device_id, g.effect, g.starts_at, g.expires_at, g.created_at, g.created_by
      FROM grants g
      WHERE g.org_id = ? AND g.revoked_at IS NULL
      ORDER BY g.created_at DESC
    `).all(params.org);

    const gpStmt = db.prepare('SELECT permission FROM grant_permissions WHERE grant_id = ?');
    const result = grants.map((g) => ({
      ...g,
      permissions: gpStmt.all(g.id).map((r) => r.permission),
    }));

    send(res, 200, { grants: result });
  });

  // DELETE /v1/orgs/:org/grants/:id — revoke
  router.delete('/v1/orgs/:org/grants/:id', async (ctx, params, res) => {
    requireOrgAccess(db, ctx, params.org);
    assertCan(db, ctx, 'grant:revoke');

    const grant = db.prepare(
      'SELECT id, user_id FROM grants WHERE id = ? AND org_id = ? AND revoked_at IS NULL'
    ).get(params.id, params.org);
    if (!grant) throw notFound('grant not found or already revoked');

    const revoke = db.transaction(() => {
      db.prepare('UPDATE grants SET revoked_at = ? WHERE id = ?').run(nowIso(), params.id);
      bumpPermVersion(db, { orgId: params.org, userId: grant.user_id });
      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'grant.revoke', targetType: 'grant', targetId: params.id, result: 'allow', requestId: ctx.requestId });
    });
    revoke();
    send(res, 200, { id: params.id });
  });
}
