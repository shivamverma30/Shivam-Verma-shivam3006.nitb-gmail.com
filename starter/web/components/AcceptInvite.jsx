import React, { useState, useEffect } from 'react';
import * as api from '../api.js';

// The public invite-acceptance screen, reached at /invite/:token.
// Shows only { orgName, role, email } — never org data (AUTH-DATA-MODEL.md §6).
// A bad token renders invite-error and leaks nothing.

export default function AcceptInvite({ token, onAccepted }) {
  const [invite, setInvite] = useState(null);
  const [error, setError] = useState(null);
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [submitError, setSubmitError] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    api.peekInvite(token)
      .then((data) => { if (!cancelled) setInvite(data); })
      .catch((err) => { if (!cancelled) setError({ code: err.code, message: err.message }); });
    return () => { cancelled = true; };
  }, [token]);

  async function handleSubmit(e) {
    e.preventDefault();
    setSubmitError(null);
    if (!name.trim() || password.length < 8) {
      setSubmitError({ message: 'name is required and password must be at least 8 characters' });
      return;
    }
    setBusy(true);
    try {
      await api.acceptInvite(token, name.trim(), password);
      // After accepting, send the user to the login screen.
      onAccepted();
    } catch (err) {
      setSubmitError({ code: err.code, message: err.message });
    } finally {
      setBusy(false);
    }
  }

  if (error) {
    return (
      <div className="login-wrap">
        <div className="login-card">
          <h1>Invitation</h1>
          <div className="error-banner" data-testid="invite-error" role="alert" aria-live="assertive">
            {error.message}
          </div>
        </div>
      </div>
    );
  }

  if (!invite) {
    return (
      <div className="login-wrap">
        <div className="login-card"><p className="sub">Loading invitation…</p></div>
      </div>
    );
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={handleSubmit}>
        <h1>You've been invited</h1>
        <p className="sub">
          Join <strong>{invite.orgName}</strong> as <span data-testid="invite-role">{invite.role}</span>.
        </p>

        {submitError && (
          <div className="error-banner" role="alert" aria-live="assertive">{submitError.message}</div>
        )}

        <div className="field">
          <label htmlFor="invite-email">Email</label>
          <input id="invite-email" data-testid="invite-email" value={invite.email} readOnly />
        </div>
        <div className="field">
          <label htmlFor="invite-name">Your name</label>
          <input id="invite-name" data-testid="invite-name" value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="invite-password">Choose a password</label>
          <input id="invite-password" data-testid="invite-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        <button className="btn" data-testid="invite-submit" type="submit" disabled={busy}>
          {busy ? 'Joining…' : 'Accept invitation'}
        </button>
      </form>
    </div>
  );
}
