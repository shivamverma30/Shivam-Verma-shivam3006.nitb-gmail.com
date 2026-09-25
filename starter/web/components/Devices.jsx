import React, { useState, useEffect, useCallback } from 'react';
import * as api from '../api.js';
import Action, { isAllowed } from './Action.jsx';

// Devices card. Each row carries the caller's resolved permissions for that device,
// so per-row action buttons (View/Control/Terminal/Transfer/Rename/Decommission) are
// present or absent based on the SERVER's resolution — not any client-side role table.

export default function Devices({ orgId, orgPermissions }) {
  const [devices, setDevices] = useState(null);
  const [error, setError] = useState(null);
  const [showAdd, setShowAdd] = useState(false);
  const [newName, setNewName] = useState('');
  const [newKind, setNewKind] = useState('linux');

  const load = useCallback(async () => {
    setError(null);
    try {
      const data = await api.listDevices(orgId);
      setDevices(data.devices);
    } catch (err) {
      setError(err.message);
      setDevices([]);
    }
  }, [orgId]);

  useEffect(() => { load(); }, [load]);

  async function startSession(deviceId, mode) {
    setError(null);
    try {
      await api.startSession(orgId, deviceId, mode);
      await load();
    } catch (err) {
      setError(err.message);
    }
  }

  async function renameDevice(deviceId) {
    const name = window.prompt('New device name');
    if (!name) return;
    setError(null);
    try {
      await api.renameDevice(orgId, deviceId, name);
      await load();
    } catch (err) { setError(err.message); }
  }

  async function decommission(deviceId) {
    if (!window.confirm('Decommission this device?')) return;
    setError(null);
    try {
      await api.decommissionDevice(orgId, deviceId);
      await load();
    } catch (err) { setError(err.message); }
  }

  async function addDevice(e) {
    e.preventDefault();
    setError(null);
    try {
      await api.provisionDevice(orgId, newName, newKind);
      setShowAdd(false);
      setNewName('');
      await load();
    } catch (err) { setError(err.message); }
  }

  if (devices === null) return <div className="empty">Loading devices…</div>;

  return (
    <div className="card-panel">
      {error && <div className="error-banner" role="alert">{error}</div>}

      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
        <h2 style={{ margin: 0 }}>Devices</h2>
        <Action permissions={orgPermissions} permission="device:provision" testId="add-device" onClick={() => setShowAdd(true)}>
          Add device
        </Action>
      </div>

      {devices.length === 0 ? (
        <div className="empty" data-testid="devices-empty">No devices yet.</div>
      ) : (
        <table>
          <thead>
            <tr><th>Name</th><th>Kind</th><th>Status</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.id} data-testid="device-row" data-device-id={d.id}>
                <td>{d.name}</td>
                <td>{d.kind}</td>
                <td>{d.online ? 'online' : 'offline'}</td>
                <td>
                  <div className="row-actions">
                    <Action permissions={d.permissions} permission="device:view" testId="start-view" onClick={() => startSession(d.id, 'view')}>View</Action>
                    <Action permissions={d.permissions} permission="device:control" testId="start-control" onClick={() => startSession(d.id, 'control')}>Control</Action>
                    <Action permissions={d.permissions} permission="device:terminal" testId="start-terminal" onClick={() => startSession(d.id, 'terminal')}>Terminal</Action>
                    <Action permissions={d.permissions} permission="device:file_transfer" testId="transfer-files" onClick={() => {}}>Transfer files</Action>
                    <Action permissions={d.permissions} permission="device:update" testId="rename-device" onClick={() => renameDevice(d.id)}>Rename</Action>
                    <Action permissions={d.permissions} permission="device:provision" testId="decommission-device" onClick={() => decommission(d.id)}>Decommission</Action>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {showAdd && (
        <div className="modal-backdrop" onClick={() => setShowAdd(false)}>
          <form className="modal" onClick={(e) => e.stopPropagation()} onSubmit={addDevice}>
            <h3>Add device</h3>
            <div className="field">
              <label>Name</label>
              <input value={newName} onChange={(e) => setNewName(e.target.value)} data-testid="device-name" />
            </div>
            <div className="field">
              <label>Kind</label>
              <select value={newKind} onChange={(e) => setNewKind(e.target.value)} data-testid="device-kind">
                {['macos', 'windows', 'linux', 'android', 'ios'].map((k) => <option key={k} value={k}>{k}</option>)}
              </select>
            </div>
            <button className="btn" type="submit" data-testid="device-submit">Create</button>
          </form>
        </div>
      )}
    </div>
  );
}
