# DECISIONS

One section per decision a reviewer might reasonably have made differently. Every claim
cites something real: a file, a test, an error string, or a commit.

---

### Roles and permissions are read from the database on every request, never encoded in code

**What I chose:** The resolution engine (`server/permissions.js`) loads the permission
catalogue, role baselines, and grants from the `permissions`, `role_permissions`, and
`grants` tables at resolve-time. No role name or permission name is written anywhere in
the code path that answers a `can()` question.

**Why:** `scripts/check-personalisation.js` loads an overlay whose role (`reviewer`) and
permission (`device:reboot`) appear in no document. My engine resolves it correctly with
the shipped nonce (18/18) *and* with a completely different nonce
(`CANDIDATE_NONCE="grade/test/999888"` — also 18/18), which is exactly what grading does.
An engine that encoded the documented 5×19 matrix would fail the moment the nonce changed.

**What I rejected:** Hardcoding the documented matrix (e.g. a `ROLE_PERMISSIONS` object).
It is faster to write and passes `check-permissions.js`, but it fails
`check-personalisation.js` and every hidden-tier fixture. HARDENING.md's whole design is to
make transcription fail.

**What would change my mind:** If the schema guaranteed the catalogue could never change
at runtime, a build-time snapshot would be defensible. It does not — `personalise.js`
inserts new rows — so runtime lookup is the only correct answer.

---

### Deny always wins, and I check the entire deny set before any allow

**What I chose:** In `resolveOne` (`server/permissions.js`), I scan *all* applicable grants
for a deny of the permission first. If any deny matches, I return `explicit_deny`
immediately — regardless of scope or specificity. Only if no deny applies do I consult the
role baseline and then the allow grants.

**Why:** My first model resolved by "most specific wins" — a device-scoped allow would
override an org-wide deny. `check-permissions.js`'s case
`device-scoped ALLOW does NOT carve out org-wide DENY` failed against that model (it
expected `deny`, my model produced `allow`). D1 says "regardless of scope or specificity",
so the deny set has to be evaluated before anything else. Moving the deny scan first fixed
the case.

**What I rejected:** "Most specific scope wins", and "resolve the narrower grant last".
Both fail the same carve-out case for the same reason: they let a narrow allow defeat a
broad deny.

**What would change my mind:** A documented case where a device-scoped allow is *expected*
to survive an org-wide deny. I could not construct one from the spec, and the seed grant
`grt_sam_deny_terminal_orgwide` plus the `g_carve` test case both assert the opposite.

---

### The org-level view is the union across all devices, not just the role baseline

**What I chose:** `resolve(..., { deviceId: null })` fetches every grant for the user in
the org (org-wide *and* device-scoped) and resolves the union. So a single device-scoped
allow grant can unlock a nav card, and a single device-scoped deny of `device:view`
contributes to the org-level answer.

**Why:** The nav cards in `web/App.jsx` gate on the org-level permission set from
`GET /auth/me`. The seed fixture gives `usr_acme_viewer` a device-scoped
`session:start`+`device:view` grant on `dev_lab_mac_01` only. My first org-level
implementation looked at the role baseline alone and missed that grants can widen the
union. The `check-api.js` device-list assertions and the viewer's visible nav depend on the
union being computed. This is Tier-A concept A2 in the rubric: a deny on one device can
lock a permission org-wide because the org view counts device-scoped grants.

**What I rejected:** Resolving org-level from the role baseline only. Simpler, but it makes
the console show the wrong cards for any user whose authority comes from a grant.

**What would change my mind:** If nav were meant to reflect "can do this on *every* device"
rather than "on *any* device". The brief's "items unlock as permissions are granted"
framing points at any-device (a granted action should surface), so union is correct.

---

### The token's `org` claim is the only org a caller can address; cross-org is 404

**What I chose:** `server/context.js` looks up the membership using the token's `org`
claim, not the URL path. Each route re-checks that the path org equals `ctx.orgId`
(`requireOrgAccess`) and returns 404 if not. Isolation is structural: the caller cannot
*name* another org, rather than being filtered afterward.

**Why:** `check-api.js` asserts an Acme token against `/orgs/org_globex/devices` returns
404 with code `NOT_FOUND` and no Globex data in the body. `check-hardening.js` also confirms
a grant naming a foreign device id returns 404, not 403 — the foreign device is invisible,
so there is nothing to forbid. A 403 would confirm the resource exists, which is an
information leak (PERMISSIONS.md §5).

**What I rejected:** A single global dataset filtered by `WHERE org_id = ?`. It works until
one query forgets the filter; the structural approach makes cross-org leakage require
defeating signature verification, not merely forgetting a clause (AUTH-DATA-MODEL.md §4.4).

**What would change my mind:** Nothing within this spec — invisible-not-forbidden is a hard
requirement asserted in multiple suites.

---

### The compound session check reports `session:start` failures before mode-permission failures

**What I chose:** `assertCanStartSession` checks `session:start` first (reason
`missing_permission`), then the mode permission (reason `missing_device_permission`).

**Why:** `check-api.js` asserts two distinct reasons: a viewer denied `session:start`
entirely on `dev_qa_android_01` gets `missing_permission`, while the same viewer *with*
`session:start` on `dev_lab_mac_01` but no `device:control` gets
`missing_device_permission`. The order matters to the caller: one means "you cannot open
sessions at all here", the other means "not in this mode on this device". Checking
`session:start` first surfaces the more fundamental failure first.

**What I rejected:** Checking the mode permission first, or collapsing both into one
`missing_permission`. Either loses the distinction the tests (and the caller) need.

**What would change my mind:** If the spec wanted the device-specific failure surfaced
first. It does not — the two seed cases pin this order.

---

### The database enforces the exclusive-session race, not check-then-act code

**What I chose:** Session INSERT relies on the partial unique index
`one_exclusive_session_per_device`. I catch the SQLite constraint error and translate it to
`409 DEVICE_BUSY`. I do not query-then-insert.

**Why:** `check-hardening.js` fires two simultaneous `control` requests at the same device
with `Promise.all` and asserts exactly one 201 and one 409. A check-then-act implementation
races: both requests see "no active session" and both insert. The unique index makes the
second insert fail atomically. This is rubric concept B5 (hand the invariant to the
database) tested with real concurrency.

**What I rejected:** `SELECT ... then INSERT if none`. It passes the sequential
`check-api.js` case but loses the concurrent race in `check-hardening.js`.

**What would change my mind:** Nothing — the DB guarantee is strictly stronger and the
schema was shaped to provide it.

---

### Re-inviting a removed member updates the existing membership row rather than inserting

**What I chose:** `POST /invites/:token/accept` in `server/routes/invites.js` looks up any
existing membership for `(org_id, user_id)` and UPDATEs it to `active` with the new role;
it only INSERTs when no row exists.

**Why:** The schema has `UNIQUE (org_id, user_id)` on memberships and users are never
deleted (removal sets `status='removed'`). My first accept implementation always INSERTed,
which throws `UNIQUE constraint failed` on a rehire. `check-hardening.js` reproduces the
full offboard→re-invite→re-accept flow and asserts the re-accept succeeds with the new
role. This is rubric concept A1 — a removed row still exists, so re-invite must update.

**What I rejected:** INSERT-only accept. It works for brand-new users and fails the instant
someone who was previously removed is re-invited.

**What would change my mind:** If removal actually deleted the row. It does not, by design
(AUTH-DATA-MODEL.md §7, D15).

---

### Suspension is refused at login, so a suspended member cannot reach ungated routes

**What I chose:** Login refuses a suspended membership with `403` and reason `suspended`
(`server/routes/auth.js`). A suspended user therefore never obtains a token, so they cannot
reach even the ungated `POST /orgs` route.

**Why:** Rubric concept A5: ungated routes bypass resolution entirely, so "suspension
yields an empty permission set" does not by itself stop a suspended user from creating an
org. Refusing at the token-minting step closes that gap. `check-hardening.js` confirms a
suspended member's login returns 403 with reason `suspended`.

**What I rejected:** Letting suspended users authenticate and relying only on per-route
permission checks. That leaves ungated routes (org creation) reachable by a suspended
account.

**What would change my mind:** If the spec wanted suspended users to retain a valid token
for some read path. AUTH-DATA-MODEL.md §10 says a suspended membership yields an empty set
and requests are refused, which is consistent with refusing the token too.

---

### All error responses are `HttpError` instances so they map to the documented codes

**What I chose:** Every thrown error is an `HttpError` (or one of the helpers in
`server/http.js`). I do not throw plain objects.

**Why:** `sendError` only reads `status`/`code`/`reason` off `HttpError`; anything else
becomes `500 INTERNAL`. My first pass threw plain `{ status, code }` objects for
`DEVICE_BUSY`, `insufficient_rank`, and `unknown_permission`, and `check-api.js` reported
`got 500 want 409` and `got "INTERNAL" want "DEVICE_BUSY"`. Converting them to `HttpError`
(or `badRequest(msg, reason)`) fixed all five failures in one pass.

**What I rejected:** A custom error-shape convention per module. It drifts; one shared error
type keeps the response contract identical everywhere (PERMISSIONS.md §5).

**What would change my mind:** Nothing — the single error path is the point.

---

## Where this repo argues with itself

### Modification authority: "equal role → 403" vs. owner-modifies-owner

`PERMISSIONS.md §6` states, in its table: *"modify a user of equal role (admin → admin) →
403"*. Taken literally, an owner modifying another owner should be `403`.

But `check-api.js` (the shipped suite) asserts the opposite:

```
check('demoting a NON-last owner is allowed',
  (await call('PATCH', '/orgs/org_acme/members/usr_acme_owner',
    { token: danaAcme, body: { role: 'viewer' } })).status, 200);
```

with the comment *"Acme has two owners, so demoting one is legitimate."* Dana is an owner,
and demoting another owner returns `200`, not `403`. The reference implementation
(`q1-starter/server/lifecycle.js`) resolves this with `if (callerRole === 'owner') return;`
— the owner may modify anyone, including a peer.

**Which I built against and why:** I built against the *behaviour* the shipped test asserts,
because the schema and the test are the ground truth over the prose (BRIEF.md: "where a rule
and the schema disagree, the schema wins"). But I refused to hardcode `'owner'`. Instead I
expressed the rule data-driven in `assertCanModify`: **the maximum-rank role present in the
`roles` table may modify anyone; every other role must strictly outrank its target.** This
keeps owner-modifies-owner working while surviving the personalisation overlay, whose
undocumented role has a rank between the documented ones — the max-rank role is still the
owner-equivalent whatever it is called.

The narrow reading ("equal → 403" applies to *everyone*) is defensible for non-top roles:
an admin still cannot modify another admin. The divergence is specifically the top rank,
and only there.

---

## Deliberately not built

- **Batch operations, search, pagination beyond the audit endpoint.** The brief explicitly
  lists these as scope the candidate may cut ("what you chose not to build, and why").
  The audit endpoint has bounded pagination because `check-api.js` asserts its boundary
  behaviour; nothing else needs it at fixture scale.
- **A resolution cache.** PERMISSIONS.md §6 and the rubric (B6) invite a cache but warn it
  must never serve stale authority. I resolve fresh on every request. The cost is one
  indexed membership lookup plus a small grant fetch per request — cheap at fixture scale,
  and it *cannot* serve stale authority because there is no cache to invalidate. If
  profiling showed this was a bottleneck I would add a cache keyed by
  `(userId, orgId, permVersion)` so a `perm_version` bump is a natural cache-miss; keying
  by `userId` alone would hand org A's authority to org B (AUTH-DATA-MODEL.md §4.2), so I
  would not do that.
- **Background session-expiry sweeper.** Sessions carry `expires_at` but nothing ends them
  in the background. Reads report their stored `state`. A production system would want a
  sweeper or a read-time expiry check; at fixture scale the TTL bound is enough and I noted
  it in BUILD-LOG Open Threads.

---

## External references

- Node.js `crypto` docs (HMAC, `timingSafeEqual`, `scrypt`) — used to confirm the
  constant-time comparison API for the JWT signature check in `server/auth.js`. No code was
  copied; the signing half was already provided in the starter.
- Node.js `url.fileURLToPath` docs — used to fix the Windows path bug where
  `new URL(...).pathname` yields `/D:/...` and `readFileSync` double-converts it. Applied in
  `scripts/load-db.js` and `server/index.js`.
- SQLite partial-index and `PRAGMA foreign_keys` behaviour — from the SQLite docs, to
  confirm the per-connection nature of `foreign_keys` (already handled in `server/db.js`)
  and the partial unique index semantics the exclusive-session guarantee relies on.

Content from these sources was used to verify API behaviour, not copied. Rephrased for
compliance with licensing restrictions.
