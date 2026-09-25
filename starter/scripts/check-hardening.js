// Adversarial edge-case suite — the "awkward cases" a hostile grader would try.
// These target the seams HARDENING.md names: offboard/rehire, self-transfer,
// suspension on ungated routes, malformed tokens, cross-scope laundering,
// concurrent exclusive-session inserts, and structural isolation.
//
//   node scripts/check-hardening.js
//
// Dependency-free, same shape as scripts/check-api.js. Spawns the server against a
// throwaway database and drives the real HTTP contract.

import { spawn, execFileSync } from 'node:child_process';
import { rmSync, existsSync } from 'node:fs';

const PORT = 8129;
const BASE = `http://localhost:${PORT}/v1`;
const DB = 'check-hardening.db';

for (const s of ['', '-wal', '-shm']) if (existsSync(DB + s)) rmSync(DB + s);
execFileSync(process.execPath, ['scripts/load-db.js'], { env: { ...process.env, DATABASE_FILE: DB }, stdio: 'ignore' });

const server = spawn(process.execPath, ['server/index.js'], {
  env: { ...process.env, DATABASE_FILE: DB, PORT: String(PORT), NODE_ENV: 'production', JWT_SECRET: 'test-secret' },
  stdio: ['ignore', 'ignore', 'inherit'],
});

await new Promise((r) => setTimeout(r, 1200));

for (const event of ['uncaughtException', 'unhandledRejection']) {
  process.on(event, (err) => {
    console.error(`\n  aborted: ${err?.message ?? err}`);
    server.kill();
    process.exit(1);
  });
}

let pass = 0, fail = 0;
const check = (label, actual, expected) => {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  ok ? pass++ : fail++;
  console.log(`${ok ? '  ok  ' : ' FAIL '} ${label.padEnd(56)}${ok ? '' : ` got ${JSON.stringify(actual)} want ${JSON.stringify(expected)}`}`);
};

async function call(method, path, { token, body, cookie } = {}) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (body) headers['content-type'] = 'application/json';
  if (cookie) headers.cookie = cookie;
  const res = await fetch(BASE + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* non-JSON */ }
  return { status: res.status, body: json, setCookie: res.headers.get('set-cookie') };
}

const login = (email, orgId, password = 'demo1234') =>
  call('POST', '/auth/login', { body: { email, password, ...(orgId ? { orgId } : {}) } });

const danaAcme = (await login('dana@example.test')).body.token;

// ---------------------------------------------------------------------------
console.log('\n== malformed token fuzzing (A6) ==');
check('garbage bearer -> 401', (await call('GET', '/orgs/org_acme/devices', { token: 'garbage' })).status, 401);
check('empty bearer -> 401', (await call('GET', '/orgs/org_acme/devices', { token: '' })).status, 401);
check('two-segment token -> 401', (await call('GET', '/orgs/org_acme/devices', { token: 'aa.bb' })).status, 401);
check('header-only base64 junk -> 401', (await call('GET', '/orgs/org_acme/devices', { token: 'eyJ.eyJ.xx' })).status, 401);
// A crafted header with a non-object shape must not crash the server (500).
check('non-object header does not 500', (await call('GET', '/orgs/org_acme/devices', { token: 'IjEi.eyJ.xx' })).status, 401);

// ---------------------------------------------------------------------------
console.log('\n== structural isolation: no cross-org laundering (A3/B4) ==');
// An owner in Acme cannot grant a permission scoped to a device in another org (404 — invisible).
const launder = await call('POST', '/orgs/org_acme/grants', {
  token: danaAcme,
  body: { userId: 'usr_acme_viewer', deviceId: 'dev_globex_desk_01', effect: 'allow', permissions: ['device:control'] },
});
check('grant naming a foreign device -> 404', launder.status, 404);

// ---------------------------------------------------------------------------
console.log('\n== no-laundering: cannot grant what you do not hold (D9) ==');
// Sam is operator in Acme (no audit:read). She cannot grant audit:read even to another user.
const samAcme = (await login('sam@example.test')).body.token;
// First give Sam grant:create so she reaches the laundering check rather than a plain 403 on the endpoint.
await call('POST', '/orgs/org_acme/grants', { token: danaAcme, body: { userId: 'usr_sam', effect: 'allow', permissions: ['grant:create'] } });
const samFresh = (await login('sam@example.test')).body.token;
const launder2 = await call('POST', '/orgs/org_acme/grants', {
  token: samFresh,
  body: { userId: 'usr_acme_viewer', effect: 'allow', permissions: ['audit:read'] },
});
check('granting a permission you lack -> 403', launder2.status, 403);

// ---------------------------------------------------------------------------
console.log('\n== offboard then re-invite updates, not inserts (A1) ==');
// Invite a brand-new user, accept, remove, then re-invite + re-accept the same email.
const inv1 = await call('POST', '/orgs/org_acme/invites', { token: danaAcme, body: { email: 'rehire@example.test', role: 'viewer' } });
const t1 = inv1.body.inviteToken;
const acc1 = await call('POST', `/invites/${t1}/accept`, { body: { name: 'Re Hire', password: 'password123' } });
check('first accept works', acc1.status, 200);
const rehireId = acc1.body.id;
check('remove the rehired member', (await call('DELETE', `/orgs/org_acme/members/${rehireId}`, { token: danaAcme })).status, 200);
// Re-invite: the membership row already exists (removed). Accept must UPDATE it, not fail on UNIQUE.
const inv2 = await call('POST', '/orgs/org_acme/invites', { token: danaAcme, body: { email: 'rehire@example.test', role: 'operator' } });
const t2 = inv2.body.inviteToken;
const acc2 = await call('POST', `/invites/${t2}/accept`, { body: { name: 'Re Hire', password: 'password123' } });
check('re-accept succeeds (update, not insert)', acc2.status, 200);
check('  ...and reflects the new role', acc2.body.role, 'operator');

// ---------------------------------------------------------------------------
console.log('\n== suspension on ungated routes (A5) ==');
// A suspended member cannot create an org (login is refused with suspended reason,
// so they cannot even obtain a token to reach the ungated /orgs route).
// Suspend the rehired operator, then confirm they cannot log in.
await call('POST', `/orgs/org_acme/members/${rehireId}/suspend`, { token: danaAcme });
const suspendedLogin = await login('rehire@example.test', null, 'password123');
check('suspended member login -> 403 suspended', suspendedLogin.status, 403);
check('  ...reason is suspended', suspendedLogin.body.error.reason, 'suspended');

// ---------------------------------------------------------------------------
console.log('\n== self-transfer / self-mutation guards ==');
// Self role change is forbidden even for an owner.
check('owner self role change -> SELF_ROLE_CHANGE', (await call('PATCH', '/orgs/org_acme/members/usr_dana', { token: danaAcme, body: { role: 'admin' } })).body.error.code, 'SELF_ROLE_CHANGE');
// Self grant is forbidden.
check('owner self grant -> 403', (await call('POST', '/orgs/org_acme/grants', { token: danaAcme, body: { userId: 'usr_dana', effect: 'allow', permissions: ['audit:read'] } })).status, 403);

// ---------------------------------------------------------------------------
console.log('\n== concurrent exclusive session inserts (D10 / B5) ==');
// Fire two control-session requests at the same device simultaneously. Exactly one 201,
// one 409 — enforced by the partial unique index, not check-then-act.
const owner = (await login('owner@acme.test')).body.token;
const [r1, r2] = await Promise.all([
  call('POST', '/orgs/org_acme/sessions', { token: owner, body: { deviceId: 'dev_lab_mac_01', mode: 'control' } }),
  call('POST', '/orgs/org_acme/sessions', { token: owner, body: { deviceId: 'dev_lab_mac_01', mode: 'control' } }),
]);
const statuses = [r1.status, r2.status].sort();
check('exactly one 201 and one 409', statuses, [201, 409]);

// ---------------------------------------------------------------------------
console.log('\n== token staleness after a permission change (B?) ==');
// Give the viewer a grant; their existing token becomes stale on the next request.
const viewerTok = (await login('viewer@acme.test')).body.token;
check('viewer token works before change', (await call('GET', '/orgs/org_acme/devices', { token: viewerTok })).status, 200);
await call('POST', '/orgs/org_acme/grants', { token: danaAcme, body: { userId: 'usr_acme_viewer', effect: 'allow', permissions: ['audit:read'] } });
const stale = await call('GET', '/orgs/org_acme/devices', { token: viewerTok });
check('stale token -> 401 TOKEN_STALE', stale.body.error.code, 'TOKEN_STALE');

// ---------------------------------------------------------------------------
console.log('\n== invisible resource: 404 not 403 for unknown ids ==');
check('unknown device -> 404', (await call('GET', '/orgs/org_acme/devices/dev_does_not_exist', { token: danaAcme })).status, 404);
check('unknown session -> 404', (await call('GET', '/sessions/ses_nope', { token: danaAcme })).status, 404);

console.log(`\n${fail === 0 ? 'ALL PASS' : 'FAILURES'} — ${pass} passed, ${fail} failed\n`);
server.kill();
process.exit(fail === 0 ? 0 : 1);
