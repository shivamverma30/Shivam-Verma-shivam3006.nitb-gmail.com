import React, { useState, useEffect, useCallback } from 'react';
import * as api from '../api.js';
import Action, { isAllowed } from './Action.jsx';

// Grants card. Shares its gate with People (user:read) because the API does — there is
// no grant:read permission (UI-INVENTORY.md §3). New-grant and revoke are separately gated.

export default function Grants({ orgId, orgPermissions, catalogue }) {
  const [grants, setGrants] = useState(null);
  const [members, setMembers] = useState([]);
  const [devices, setDevices] = useState([]);
  const [error, setError] = useState(null);
  const [showNew, setShowNew] = useState(false);

  // new-grant form state
  const [gUser, setGUser] = useState('');
  const [gDevice, setGDevice] = useState('');
  const [gEffect, setGEffect] = useState('allow');
  const [gPerms, setGPerms] = useState([]);

  const load = useCallback(async () => {
    setError(null);
    try {
      const data = await api.listGrants(orgId);
      setGrants(data.grants);
    } catch (err) {
      setError(err.message);
      setGrants([]);
    }
  }, [orgId]);

  useEffect(() => { load(); }, [load]);

  // Load members and devices for the new-grant form when it opens
  useEffect(() => {
    if (!showNew) return;
    api.listMembers(orgId).then((d) => setMembers(d.members)).catch(() => {});
    api.listDevices(orgId).then((d) => setDevices(d.devices)).catch(() => {});
  }, [showNew, orgId]);

  async function revoke(id) {
    setError(null);
    try { await api.revokeGrant(orgId, id); await load(); }
    catch (err) { setError(err.message); }
  }

  function togglePerm(key) {
    setGPerms((prev) => prev.includes(key) ? prev.filter((p) => p !== key) : [...prev, key]);
  }

  async function submitGrant(e) {
    e.preventDefault();
    setError(null);
    try {
      await api.createGrant(orgId, {
        userId: gUser,
        deviceId: gDevice || undefined,
        effect: gEffect,
        permissions: gPerms,
      });
      setShowNew(false);
      setGPerms([]);
      setGUser('');
      setGDevice('');
      await load();
    } catch (err) { setError(err.message); }
  }

  if (grants === null) return <div className="empty">Loading grants…</div>;

  const permKeys = catalogue ?? [];

  return (
    <div className="card-panel">
      {error && <div className="error-banner" role="alert">{error}</div>}

      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
        <h2 style={{ margin: 0 }}>Grants</h2>
        <Action permissions={orgPermissions} permission="grant:create" testId="new-grant" onClick={() => setShowNew(true)}>
          New grant
        </Action>
      </div>

      {grants.length === 0 ? (
        <div className="empty">No grants.</div>
      ) : (
        <table>
          <thead><tr><th>User</th><th>Device</th><th>Effect</th><th>Permissions</th><th></th></tr></thead>
          <tbody>
            {grants.map((g) => (
              <tr key={g.id} data-testid="grant-row" data-effect={g.effect} data-grant-id={g.id}>
                <td>{g.user_id}</td>
                <td>{g.device_id ?? 'org-wide'}</td>
                <td><span className={`tag ${g.effect}`}>{g.effect}</span></td>
                <td>{g.permissions.join(', ')}</td>
                <td>
                  <Action permissions={orgPermissions} permission="grant:revoke" testId="revoke-grant" className="btn small danger" onClick={() => revoke(g.id)}>
                    Revoke
                  </Action>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {showNew && (
        <div className="modal-backdrop" onClick={() => setShowNew(false)}>
          <form className="modal" onClick={(e) => e.stopPropagation()} onSubmit={submitGrant}>
            <h3>New grant</h3>
            <div className="field">
              <label>User</label>
              <select value={gUser} onChange={(e) => setGUser(e.target.value)} data-testid="grant-user" required>
                <option value="">Select a user…</option>
                {members.map((m) => <option key={m.id} value={m.id}>{m.name} ({m.role})</option>)}
              </select>
            </div>
            <div className="field">
              <label>Device (optional — leave blank for org-wide)</label>
              <select value={gDevice} onChange={(e) => setGDevice(e.target.value)} data-testid="grant-device">
                <option value="">Org-wide</option>
                {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
              </select>
            </div>
            <div className="field">
              <label>Effect</label>
              <select value={gEffect} onChange={(e) => setGEffect(e.target.value)} data-testid="grant-effect">
                <option value="allow">allow</option>
                <option value="deny">deny</option>
              </select>
            </div>
            <div className="field">
              <label>Permissions</label>
              <div className="checkbox-list">
                {permKeys.map((k) => (
                  <label key={k}>
                    <input
                      type="checkbox"
                      data-permission-key={k}
                      checked={gPerms.includes(k)}
                      onChange={() => togglePerm(k)}
                    />
                    {k}
                  </label>
                ))}
              </div>
            </div>
            <button className="btn" type="submit" data-testid="grant-submit">Create grant</button>
          </form>
        </div>
      )}
    </div>
  );
}
