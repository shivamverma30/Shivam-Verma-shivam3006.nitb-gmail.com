import React, { useState } from 'react';
import * as api from '../api.js';

// The sign-in screen. Failure feedback is NOT permission-gated (UI-INVENTORY.md §4):
// a failed sign-in must render login-error with the server's reason, and it stays on
// screen until the next attempt. A wrong password and an unknown account read identically
// (the server returns the same response) to avoid an account enumeration oracle.

export default function Login({ onAuthenticated }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);

    // Client-side presence check so an empty form says what is missing.
    if (!email.trim() || !password) {
      setError({ code: 'VALIDATION', message: 'email and password are required' });
      return;
    }

    setBusy(true);
    try {
      const result = await api.login(email.trim(), password);
      api.setToken(result.token);
      onAuthenticated(result);
    } catch (err) {
      // Surface the server's reason verbatim — do not improve on it.
      setError({ code: err.code, message: err.message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-wrap">
      <form className="login-card" data-testid="login-form" onSubmit={handleSubmit}>
        <h1>RemoteOps</h1>
        <p className="sub">Sign in to your organization console.</p>

        {error && (
          <div
            className="error-banner"
            data-testid="login-error"
            data-error-code={error.code}
            role="alert"
            aria-live="assertive"
          >
            {error.message}
          </div>
        )}

        <div className="field">
          <label htmlFor="login-email">Email</label>
          <input
            id="login-email"
            data-testid="login-email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="username"
          />
        </div>

        <div className="field">
          <label htmlFor="login-password">Password</label>
          <input
            id="login-password"
            data-testid="login-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </div>

        <button className="btn" data-testid="login-submit" type="submit" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  );
}
