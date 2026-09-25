import React, { useState, useEffect, useCallback } from 'react';
import * as api from '../api.js';

// Audit card (gated by audit:read). Read-only log of allow and deny events.

export default function Audit({ orgId }) {
  const [events, setEvents] = useState(null);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const data = await api.listAudit(orgId, 100, 0);
      setEvents(data.events);
    } catch (err) {
      setError(err.message);
      setEvents([]);
    }
  }, [orgId]);

  useEffect(() => { load(); }, [load]);

  if (events === null) return <div className="empty">Loading audit log…</div>;

  return (
    <div className="card-panel">
      {error && <div className="error-banner" role="alert">{error}</div>}
      <h2 style={{ marginTop: 0 }}>Audit log</h2>

      {events.length === 0 ? (
        <div className="empty">No audit events.</div>
      ) : (
        <table>
          <thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Result</th><th>Reason</th></tr></thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id} data-testid="audit-row" data-audit-id={e.id}>
                <td>{e.at?.slice(0, 19).replace('T', ' ')}</td>
                <td>{e.actor_id ?? '—'}</td>
                <td>{e.action}</td>
                <td>{e.target_id ?? '—'}</td>
                <td><span className={`tag ${e.result === 'deny' ? 'deny' : 'allow'}`}>{e.result}</span></td>
                <td>{e.reason_code ?? '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
