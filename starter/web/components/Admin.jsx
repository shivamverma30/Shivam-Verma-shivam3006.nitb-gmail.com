import React, { useState } from 'react';
import * as api from '../api.js';
import Action from './Action.jsx';

// Admin card. Visible for org:update OR org:delete (UI-INVENTORY.md §2).
// Rename is gated by org:update; Delete by org:delete. This is the one card where
// admin (has org:update) and owner (has both) differ visibly.

export default function Admin({ orgId, orgName, orgPermissions, onOrgChanged }) {
  const [error, setError] = useState(null);

  async function rename() {
    const name = window.prompt('New organization name', orgName);
    if (!name) return;
    setError(null);
    try {
      await api.renameOrg(orgId, name);
      onOrgChanged?.();
    } catch (err) { setError(err.message); }
  }

  async function del() {
    if (!window.confirm(`Delete "${orgName}"? This cannot be undone.`)) return;
    setError(null);
    try {
      await api.deleteOrg(orgId);
      onOrgChanged?.({ deleted: true });
    } catch (err) { setError(err.message); }
  }

  return (
    <div className="card-panel">
      {error && <div className="error-banner" role="alert">{error}</div>}
      <h2 style={{ marginTop: 0 }}>Admin</h2>
      <p className="sub">Organization settings for <strong>{orgName}</strong>.</p>

      <div className="row-actions">
        <Action permissions={orgPermissions} permission="org:update" testId="rename-org" onClick={rename}>
          Rename org
        </Action>
        <Action permissions={orgPermissions} permission="org:delete" testId="delete-org" className="btn small danger" onClick={del}>
          Delete org
        </Action>
      </div>
    </div>
  );
}
