import React, { useState, useEffect, useCallback } from 'react';
import * as api from '../api.js';
import Action, { isAllowed } from './Action.jsx';

// People card (gated by user:read). Member rows plus role-change, suspend, remove,
// and invite — each gated by the server's org-level resolved permissions.

export default function People({ orgId, orgPermissions, roles }) {
  const [members, setMembers] = useState(null);
  const [error, setError] = useState(null);
  const [showInvite, setShowInvite] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState('viewer');
  const [inviteToken, setInviteToken] = useState(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const data = await api.listMembers(orgId);
      setMembers(data.members);
    } catch (err) {
      setError(err.message);
      setMembers([]);
    }
  }, [orgId]);

  useEffect(() => { load(); }, [load]);

  async function changeRole(userId, role) {
    setError(null);
    try { await api.changeRole(orgId, userId, role); await load(); }
    catch (err) { setError(err.message); }
  }

  async function toggleSuspend(m) {
    setError(null);
    try {
      if (m.status === 'suspended') await api.reinstateMember(orgId, m.id);
      else await api.suspendMember(orgId, m.id);
      await load();
    } catch (err) { setError(err.message); }
  }

  async function remove(userId) {
    if (!window.confirm('Remove this member?')) return;
    setError(null);
    try { await api.removeMember(orgId, userId); await load(); }
    catch (err) { setError(err.message); }
  }

  async function submitInvite(e) {
    e.preventDefault();
    setError(null);
    try {
      const result = await api.createInvite(orgId, inviteEmail, inviteRole);
      setInviteToken(result.inviteToken);
      setInviteEmail('');
    } catch (err) { setError(err.message); }
  }

  if (members === null) return <div className="empty">Loading members…</div>;

  const canManageRole = isAllowed(orgPermissions, 'user:role:update');
  const roleKeys = roles ?? ['owner', 'admin', 'operator', 'auditor', 'viewer'];

  return (
    <div className="card-panel">
      {error && <div className="error-banner" role="alert">{error}</div>}

      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
        <h2 style={{ margin: 0 }}>People</h2>
        <Action permissions={orgPermissions} permission="user:invite" testId="invite-user" onClick={() => { setShowInvite(true); setInviteToken(null); }}>
          Invite
        </Action>
      </div>

      <table>
        <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody>
          {members.map((m) => (
            <tr key={m.id} data-testid="user-row" data-user-id={m.id}>
              <td>{m.name}</td>
              <td>{m.email}</td>
              <td>
                {canManageRole ? (
                  <select
                    data-testid="role-select"
                    data-permission="user:role:update"
                    data-state="unlocked"
                    value={m.role}
                    onChange={(e) => changeRole(m.id, e.target.value)}
                  >
                    {roleKeys.map((r) => <option key={r} value={r}>{r}</option>)}
                  </select>
                ) : m.role}
              </td>
              <td>{m.status}</td>
              <td>
                <div className="row-actions">
                  <Action permissions={orgPermissions} permission="user:remove" testId="suspend-user" onClick={() => toggleSuspend(m)}>
                    {m.status === 'suspended' ? 'Reinstate' : 'Suspend'}
                  </Action>
                  <Action permissions={orgPermissions} permission="user:remove" testId="remove-user" onClick={() => remove(m.id)}>
                    Remove
                  </Action>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {showInvite && (
        <div className="modal-backdrop" onClick={() => setShowInvite(false)}>
          <form className="modal" onClick={(e) => e.stopPropagation()} onSubmit={submitInvite}>
            <h3>Invite a person</h3>
            {inviteToken ? (
              <>
                <p className="sub">Share this one-time invite link:</p>
                <div className="field">
                  <input readOnly value={`${window.location.origin}/invite/${inviteToken}`} data-testid="invite-link" />
                </div>
                <button type="button" className="btn" onClick={() => { setShowInvite(false); load(); }}>Done</button>
              </>
            ) : (
              <>
                <div className="field">
                  <label>Email</label>
                  <input value={inviteEmail} onChange={(e) => setInviteEmail(e.target.value)} data-testid="invite-email-input" />
                </div>
                <div className="field">
                  <label>Role</label>
                  <select value={inviteRole} onChange={(e) => setInviteRole(e.target.value)} data-testid="invite-role-select">
                    {roleKeys.map((r) => <option key={r} value={r}>{r}</option>)}
                  </select>
                </div>
                <button className="btn" type="submit" data-testid="invite-send">Send invite</button>
              </>
            )}
          </form>
        </div>
      )}
    </div>
  );
}
