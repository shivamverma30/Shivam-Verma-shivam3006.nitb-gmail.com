import React, { useState, useEffect, useCallback } from 'react';
import * as api from '../api.js';
import Action, { isAllowed } from './Action.jsx';

// Sessions card (gated by session:view). Session rows plus stop actions:
// your own session can always be stopped; someone else's needs session:terminate.

export default function Sessions({ orgId, orgPermissions, currentUserId }) {
  const [sessions, setSessions] = useState(null);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const data = await api.listSessions(orgId);
      setSessions(data.sessions);
    } catch (err) {
      setError(err.message);
      setSessions([]);
    }
  }, [orgId]);

  useEffect(() => { load(); }, [load]);

  async function stop(id) {
    setError(null);
    try { await api.stopSession(id); await load(); }
    catch (err) { setError(err.message); }
  }

  if (sessions === null) return <div className="empty">Loading sessions…</div>;

  const canTerminate = isAllowed(orgPermissions, 'session:terminate');

  return (
    <div className="card-panel">
      {error && <div className="error-banner" role="alert">{error}</div>}
      <h2 style={{ marginTop: 0 }}>Sessions</h2>

      {sessions.length === 0 ? (
        <div className="empty">No sessions.</div>
      ) : (
        <table>
          <thead><tr><th>User</th><th>Device</th><th>Mode</th><th>State</th><th>Started</th><th></th></tr></thead>
          <tbody>
            {sessions.map((s) => {
              const isMine = s.user_id === currentUserId;
              const canStop = s.state === 'active' && (isMine || canTerminate);
              return (
                <tr key={s.id} data-testid="session-row" data-session-id={s.id}>
                  <td>{s.user_id}</td>
                  <td>{s.device_id}</td>
                  <td>{s.mode}</td>
                  <td>{s.state}</td>
                  <td>{s.started_at?.slice(0, 16).replace('T', ' ')}</td>
                  <td>
                    {canStop && (
                      <button
                        data-testid="stop-session"
                        data-permission={isMine ? undefined : 'session:terminate'}
                        data-state="unlocked"
                        className="btn small danger"
                        onClick={() => stop(s.id)}
                      >
                        Stop
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}
