// Session routes.
//
// POST   /v1/orgs/:org/sessions     — start session (session:start + mode permission)
// GET    /v1/orgs/:org/sessions     — list sessions (session:view)
// GET    /v1/sessions/:id           — get session (participant or session:view)
// DELETE /v1/sessions/:id           — stop session (own session or session:terminate)

import { send, notFound, forbidden, badRequest, HttpError } from '../http.js';
import { newId, nowIso } from '../db.js';
import { assertCanStartSession, assertCan } from '../permissions.js';
import { snapshotAuthority, sessionExpiry } from '../lifecycle.js';
import { audit, auditDenials } from '../audit.js';

function requireOrgAccess(db, ctx, orgId) {
  if (orgId !== ctx.orgId) throw notFound('org not found');
  const org = db.prepare('SELECT id FROM organizations WHERE id = ? AND deleted_at IS NULL').get(orgId);
  if (!org) throw notFound('org not found');
  return org;
}

export function registerSessionRoutes(router, { db, secret }) {
  // POST /v1/orgs/:org/sessions — start a session
  router.post('/v1/orgs/:org/sessions', async (ctx, params, res) => {
    requireOrgAccess(db, ctx, params.org);

    const { deviceId, mode } = ctx.body;
    if (!deviceId) throw badRequest('deviceId is required');
    if (!mode || !['view', 'control', 'terminal'].includes(mode)) {
      throw badRequest('mode must be view, control, or terminal');
    }

    // Verify device belongs to this org
    const device = db.prepare(
      'SELECT id FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL'
    ).get(deviceId, params.org);
    if (!device) throw notFound('device not found');

    // Compound permission check with distinguishable failure reasons
    // auditDenials wraps the check and records denied attempts
    auditDenials(db, ctx, { action: 'session.start', targetType: 'device', targetId: deviceId }, () => {
      assertCanStartSession(db, ctx, mode, deviceId);
    });

    const sessionId = newId('ses');
    const expiresAt = sessionExpiry(db, params.org);
    const now = nowIso();
    const authorizedBy = snapshotAuthority(db, { userId: ctx.userId, orgId: params.org, deviceId });

    const create = db.transaction(() => {
      db.prepare(`
        INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, started_at, expires_at)
        VALUES (?,?,?,?,?,?,?,?,?)
      `).run(sessionId, params.org, ctx.userId, deviceId, mode, 'active', JSON.stringify(authorizedBy), now, expiresAt);

      audit(db, {
        orgId: params.org,
        actorId: ctx.userId,
        action: 'session.start',
        targetType: 'device',
        targetId: deviceId,
        result: 'allow',
        requestId: ctx.requestId,
      });
    });

    try {
      create();
    } catch (err) {
      // The unique index one_exclusive_session_per_device fires here for control/terminal
      if (err?.code === 'SQLITE_CONSTRAINT_UNIQUE' || err?.message?.includes('one_exclusive_session')) {
        // Find the holder session
        const holder = db.prepare(
          `SELECT id FROM sessions WHERE device_id = ? AND state = 'active' AND mode IN ('control','terminal')`
        ).get(deviceId);
        const busy = new HttpError(409, 'DEVICE_BUSY', 'device already has an exclusive session', null);
        busy.holderId = holder?.id;
        throw busy;
      }
      throw err;
    }

    const session = db.prepare('SELECT id, org_id, user_id, device_id, mode, state, started_at, expires_at FROM sessions WHERE id = ?').get(sessionId);
    send(res, 201, session);
  });

  // GET /v1/orgs/:org/sessions
  router.get('/v1/orgs/:org/sessions', async (ctx, params, res) => {
    requireOrgAccess(db, ctx, params.org);
    assertCan(db, ctx, 'session:view');

    const sessions = db.prepare(`
      SELECT id, user_id, device_id, mode, state, end_reason, started_at, expires_at, ended_at
      FROM sessions
      WHERE org_id = ?
      ORDER BY started_at DESC
    `).all(params.org);

    send(res, 200, { sessions });
  });

  // GET /v1/sessions/:id — readable by participant or session:view
  router.get('/v1/sessions/:id', async (ctx, _params, res) => {
    const session = db.prepare(
      'SELECT id, org_id, user_id, device_id, mode, state, end_reason, authorized_by, started_at, expires_at, ended_at FROM sessions WHERE id = ?'
    ).get(_params.id);

    if (!session) throw notFound('session not found');

    // Structural isolation: session must be in caller's org
    if (session.org_id !== ctx.orgId) throw notFound('session not found');

    // Must be participant or have session:view
    const isParticipant = session.user_id === ctx.userId;
    if (!isParticipant) {
      assertCan(db, ctx, 'session:view');
    }

    send(res, 200, {
      id: session.id,
      org_id: session.org_id,
      user_id: session.user_id,
      device_id: session.device_id,
      mode: session.mode,
      state: session.state,
      end_reason: session.end_reason,
      started_at: session.started_at,
      expires_at: session.expires_at,
      ended_at: session.ended_at,
    });
  });

  // DELETE /v1/sessions/:id — stop a session (own or session:terminate)
  router.delete('/v1/sessions/:id', async (ctx, _params, res) => {
    const session = db.prepare(
      `SELECT id, org_id, user_id, device_id, mode, state FROM sessions WHERE id = ? AND state = 'active'`
    ).get(_params.id);

    if (!session) throw notFound('session not found or not active');

    // Structural isolation
    if (session.org_id !== ctx.orgId) throw notFound('session not found');

    const isOwner = session.user_id === ctx.userId;
    if (!isOwner) {
      assertCan(db, ctx, 'session:terminate');
    }

    const end = db.transaction(() => {
      db.prepare(
        `UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ? WHERE id = ?`
      ).run(isOwner ? 'user_stopped' : 'admin_terminated', nowIso(), session.id);

      audit(db, {
        orgId: session.org_id,
        actorId: ctx.userId,
        action: 'session.stop',
        targetType: 'session',
        targetId: session.id,
        result: 'allow',
        requestId: ctx.requestId,
      });
    });
    end();

    send(res, 200, { id: session.id, end_reason: isOwner ? 'user_stopped' : 'admin_terminated' });
  });
}
