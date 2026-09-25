// Append-only audit writes.
//
// Audit events record BOTH allow and deny (PERMISSIONS.md invariant 9, §8).
// The audit_events table has BEFORE UPDATE and BEFORE DELETE triggers — the database
// enforces append-only, so this module only ever INSERTs.
//
// One action = one row. Write the success row inside the same transaction as the
// change it describes. For denials, the auditDenials wrapper catches the permission
// error, writes the deny row, then rethrows.

import { newId, nowIso } from './db.js';
import { HttpError } from './http.js';

// ---------------------------------------------------------------------------
// audit — write one audit row. Synchronous (better-sqlite3 is sync).
// ---------------------------------------------------------------------------
export function audit(db, { orgId, actorId, action, targetType, targetId, result, reasonCode, requestId }) {
  db.prepare(`
    INSERT INTO audit_events (id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id, at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    newId('aud'),
    orgId,
    actorId ?? null,
    action,
    targetType ?? null,
    targetId ?? null,
    result,
    reasonCode ?? null,
    requestId ?? null,
    nowIso(),
  );
}

// ---------------------------------------------------------------------------
// auditDenials — run fn(); if it throws a 403 FORBIDDEN, record the denial
// before rethrowing. Other errors are rethrown without an audit row.
//
// ctx must carry { userId, orgId, requestId }.
// meta must carry { action, targetType, targetId }.
// ---------------------------------------------------------------------------
export function auditDenials(db, ctx, meta, fn) {
  try {
    return fn();
  } catch (err) {
    if (err instanceof HttpError && err.status === 403) {
      try {
        audit(db, {
          orgId: ctx.orgId,
          actorId: ctx.userId,
          action: meta.action,
          targetType: meta.targetType ?? null,
          targetId: meta.targetId ?? null,
          result: 'deny',
          reasonCode: err.reason ?? 'missing_permission',
          requestId: ctx.requestId ?? null,
        });
      } catch {
        // Audit write failures must not mask the original permission error
      }
    }
    throw err;
  }
}
