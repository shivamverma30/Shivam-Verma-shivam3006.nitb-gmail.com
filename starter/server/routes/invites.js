// Invite routes.
//
// POST   /v1/orgs/:org/invites          — create invite (user:invite)
// GET    /v1/orgs/:org/invites          — list org invites (user:invite)
// DELETE /v1/orgs/:org/invites/:id      — cancel invite (user:invite)
// GET    /v1/invites/:token             — public: peek at invite details
// POST   /v1/invites/:token/accept      — public: accept invite, create/join account

import { send, notFound, badRequest, conflict, gone, forbidden } from '../http.js';
import { newId, nowIso } from '../db.js';
import { newInviteToken, hashInviteToken, hashPassword, issueAccessToken, REFRESH_TTL_SECONDS, newRefreshToken, hashRefreshToken } from '../auth.js';
import { assertCan } from '../permissions.js';
import { assertRoleExists, assertCanModify, assertCanAssignRole } from '../lifecycle.js';
import { audit } from '../audit.js';
import { issueTokensAndRespond } from './auth.js';

const INVITE_TTL_DAYS = 7;

function requireOrgAccess(db, ctx, orgId) {
  if (orgId !== ctx.orgId) throw notFound('org not found');
  const org = db.prepare('SELECT id, name FROM organizations WHERE id = ? AND deleted_at IS NULL').get(orgId);
  if (!org) throw notFound('org not found');
  return org;
}

export function registerInviteRoutes(router, { db, secret }) {
  // POST /v1/orgs/:org/invites
  router.post('/v1/orgs/:org/invites', async (ctx, params, res) => {
    const org = requireOrgAccess(db, ctx, params.org);
    assertCan(db, ctx, 'user:invite');

    const { email, role } = ctx.body;
    if (!email || typeof email !== 'string') throw badRequest('email is required');
    if (!role || typeof role !== 'string') throw badRequest('role is required');

    const normalEmail = email.toLowerCase().trim();
    if (!normalEmail.includes('@')) throw badRequest('invalid email format');

    assertRoleExists(db, role);
    // Can only invite to a role you could assign
    assertCanAssignRole(db, ctx.role, role);
    assertCanModify(db, ctx.role, role);

    // Check for existing active membership
    const existingMem = db.prepare(
      `SELECT id, status FROM memberships WHERE org_id = ? AND user_id = (SELECT id FROM users WHERE email = ?) AND status != 'removed'`
    ).get(params.org, normalEmail);
    if (existingMem && existingMem.status === 'active') {
      throw conflict('user is already an active member of this org');
    }

    // Check for an existing live invite
    const existingInvite = db.prepare(
      `SELECT id FROM invites WHERE org_id = ? AND email = ? AND accepted_at IS NULL AND revoked_at IS NULL`
    ).get(params.org, normalEmail);
    if (existingInvite) {
      throw conflict('a live invite already exists for this email');
    }

    const raw = newInviteToken();
    const tokenHash = hashInviteToken(raw);
    const expiresAt = new Date(Date.now() + INVITE_TTL_DAYS * 24 * 60 * 60 * 1000).toISOString();

    const create = db.transaction(() => {
      db.prepare(
        'INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at) VALUES (?,?,?,?,?,?,?)'
      ).run(newId('inv'), params.org, normalEmail, role, tokenHash, ctx.userId, expiresAt);

      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'invite.create', targetType: 'invite', result: 'allow', requestId: ctx.requestId });
    });
    create();

    // Return the raw token ONCE — never again (AUTH-DATA-MODEL.md §6)
    send(res, 201, { inviteToken: raw, email: normalEmail, role, expiresAt });
  });

  // GET /v1/orgs/:org/invites
  router.get('/v1/orgs/:org/invites', async (ctx, params, res) => {
    requireOrgAccess(db, ctx, params.org);
    assertCan(db, ctx, 'user:invite');

    const invites = db.prepare(`
      SELECT id, email, role, expires_at, accepted_at, revoked_at, created_at
      FROM invites
      WHERE org_id = ? AND revoked_at IS NULL AND accepted_at IS NULL
      ORDER BY created_at DESC
    `).all(params.org);

    send(res, 200, { invites });
  });

  // DELETE /v1/orgs/:org/invites/:id
  router.delete('/v1/orgs/:org/invites/:id', async (ctx, params, res) => {
    requireOrgAccess(db, ctx, params.org);
    assertCan(db, ctx, 'user:invite');

    const invite = db.prepare(
      `SELECT id FROM invites WHERE id = ? AND org_id = ? AND revoked_at IS NULL AND accepted_at IS NULL`
    ).get(params.id, params.org);
    if (!invite) throw notFound('invite not found or already used');

    const cancel = db.transaction(() => {
      db.prepare('UPDATE invites SET revoked_at = ? WHERE id = ?').run(nowIso(), params.id);
      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'invite.cancel', targetType: 'invite', targetId: params.id, result: 'allow', requestId: ctx.requestId });
    });
    cancel();
    send(res, 200, { id: params.id });
  });

  // GET /v1/invites/:token — public: show invite details (no org data)
  router.get('/v1/invites/:token', async (ctx, params, res) => {
    const hash = hashInviteToken(params.token);
    const invite = db.prepare(`
      SELECT i.id, i.email, i.role, i.expires_at, i.accepted_at, i.revoked_at, o.name AS org_name
      FROM invites i
      JOIN organizations o ON o.id = i.org_id
      WHERE i.token_hash = ?
    `).get(hash);

    if (!invite) throw notFound('invite not found');

    // Minimal response — just enough to render the accept page (AUTH-DATA-MODEL.md §6)
    // No org id, no device counts, no member list
    const now = nowIso();
    if (invite.accepted_at || invite.revoked_at || invite.expires_at <= now) {
      // If accepted already, distinguish with 409
      if (invite.accepted_at) throw conflict('invite already accepted');
      throw gone('invite is no longer valid');
    }

    send(res, 200, {
      orgName: invite.org_name,
      role: invite.role,
      email: invite.email,
      expiresAt: invite.expires_at,
    });
  });

  // POST /v1/invites/:token/accept — public: accept and create account
  router.post('/v1/invites/:token/accept', async (ctx, params, res) => {
    const hash = hashInviteToken(params.token);
    const invite = db.prepare(`
      SELECT i.id, i.org_id, i.email, i.role, i.expires_at, i.accepted_at, i.revoked_at
      FROM invites i
      WHERE i.token_hash = ?
    `).get(hash);

    if (!invite) throw notFound('invite not found');
    const now = nowIso();
    if (invite.accepted_at) throw conflict('invite already accepted');
    if (invite.revoked_at || invite.expires_at <= now) throw gone('invite is no longer valid');

    const { name, password } = ctx.body;
    if (!name || typeof name !== 'string' || !name.trim()) throw badRequest('name is required');
    if (!password || typeof password !== 'string' || password.length < 8) {
      throw badRequest('password must be at least 8 characters');
    }

    let userId;
    const accept = db.transaction(() => {
      // Find or create the user
      const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(invite.email);
      if (existing) {
        userId = existing.id;
      } else {
        userId = newId('usr');
        const pwHash = hashPassword(password);
        db.prepare('INSERT INTO users (id, email, name, password_hash) VALUES (?,?,?,?)')
          .run(userId, invite.email, name.trim(), pwHash);
      }

      // Upsert the membership (may already exist as 'removed' or 'invited')
      const existingMem = db.prepare(
        'SELECT id, status FROM memberships WHERE org_id = ? AND user_id = ?'
      ).get(invite.org_id, userId);

      if (existingMem) {
        db.prepare(
          "UPDATE memberships SET role = ?, status = 'active', perm_version = perm_version + 1, joined_at = ? WHERE id = ?"
        ).run(invite.role, now, existingMem.id);
      } else {
        db.prepare(
          'INSERT INTO memberships (id, org_id, user_id, role, status, joined_at) VALUES (?,?,?,?,?,?)'
        ).run(newId('mem'), invite.org_id, userId, invite.role, 'active', now);
      }

      // Mark invite as accepted — single-use
      db.prepare('UPDATE invites SET accepted_at = ?, accepted_by = ? WHERE id = ?')
        .run(now, userId, invite.id);

      audit(db, { orgId: invite.org_id, actorId: userId, action: 'invite.accept', targetType: 'invite', targetId: invite.id, result: 'allow', requestId: ctx.requestId });
    });
    accept();

    // Issue tokens and return the me shape
    issueTokensAndRespond(db, secret, res, { userId, orgId: invite.org_id, requestId: ctx.requestId });
  });
}
