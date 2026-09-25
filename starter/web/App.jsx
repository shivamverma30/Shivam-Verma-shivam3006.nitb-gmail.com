import React, { useState, useEffect, useCallback } from 'react';
import * as api from './api.js';
import { isAllowed } from './components/Action.jsx';
import Login from './components/Login.jsx';
import AcceptInvite from './components/AcceptInvite.jsx';
import Devices from './components/Devices.jsx';
import People from './components/People.jsx';
import Grants from './components/Grants.jsx';
import Sessions from './components/Sessions.jsx';
import Audit from './components/Audit.jsx';
import Admin from './components/Admin.jsx';

// The console shell.
//
// Presence is server-driven: `session.permissions` is the org-level resolved set from
// GET /auth/me (or /auth/token on switch). Nav cards are shown based on that set.
// There is NO role-to-permission table here — every gate reads session.permissions.
//
// Per-org identity: the shell carries data-org-id and data-org-theme, and styles.css
// maps the theme to a distinct background so switching orgs is visibly different.
//
// Token storage: the access token lives in api.js memory only. The refresh token is an
// httpOnly cookie. On mount we try /auth/refresh so a reload restores the session.

// Card definitions: which nav card, its testid, and the permission that governs it.
// Admin is special: it appears for org:update OR org:delete.
const CARDS = [
  { key: 'devices', label: 'Devices', permission: 'device:list' },
  { key: 'people', label: 'People', permission: 'user:read' },
  { key: 'grants', label: 'Grants', permission: 'user:read' },
  { key: 'sessions', label: 'Sessions', permission: 'session:view' },
  { key: 'audit', label: 'Audit', permission: 'audit:read' },
  { key: 'admin', label: 'Admin', permission: null }, // org:update OR org:delete
];

function cardVisible(card, permissions) {
  if (card.key === 'admin') {
    return isAllowed(permissions, 'org:update') || isAllowed(permissions, 'org:delete');
  }
  return isAllowed(permissions, card.permission);
}

// Derive the permission catalogue (all keys) from the resolved set.
function catalogueFrom(permissions) {
  return Object.keys(permissions ?? {}).sort();
}

// Derive the set of role keys the server knows about — used for role selects.
// We don't have a roles endpoint, so we read them from the orgs the user is in plus
// a conservative default. The server validates on submit regardless.
const DEFAULT_ROLES = ['owner', 'admin', 'operator', 'auditor', 'viewer'];

export default function App() {
  const [session, setSession] = useState(null); // the /me response
  const [loading, setLoading] = useState(true);
  const [activeCard, setActiveCard] = useState('devices');
  const [route, setRoute] = useState(window.location.pathname);

  // Handle the /invite/:token route
  useEffect(() => {
    const onPop = () => setRoute(window.location.pathname);
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);

  // On mount, try to restore the session from the refresh cookie.
  // Skip on the invite route and on the explicit /login route (after accepting an
  // invite, the user is deliberately sent to a fresh sign-in rather than auto-logged in).
  useEffect(() => {
    if (route.startsWith('/invite/') || route === '/login') { setLoading(false); return; }
    let cancelled = false;
    api.refresh()
      .then((result) => {
        if (cancelled) return;
        api.setToken(result.token);
        setSession(result);
      })
      .catch(() => { /* no valid refresh cookie — show login */ })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [route]);

  const reloadSession = useCallback(async () => {
    try {
      const fresh = await api.me();
      setSession(fresh);
    } catch (err) {
      // token stale — refresh
      try {
        const r = await api.refresh();
        api.setToken(r.token);
        setSession(r);
      } catch {
        api.clearToken();
        setSession(null);
      }
    }
  }, []);

  async function handleSwitchOrg(orgId) {
    try {
      const result = await api.switchOrg(orgId);
      api.setToken(result.token);
      setSession(result);
      // Reset to a card that's visible in the new org
      setActiveCard('devices');
    } catch (err) {
      // If switching fails, surface it — but keep the current session
      console.error('org switch failed:', err.message);
    }
  }

  async function handleCreateOrg() {
    const name = window.prompt('New organization name');
    if (!name) return;
    try {
      const result = await api.createOrg(name);
      api.setToken(result.token);
      // Fetch the full /me for the new org
      const fresh = await api.me();
      setSession(fresh);
      setActiveCard('devices');
    } catch (err) {
      console.error('create org failed:', err.message);
    }
  }

  function handleSignOut() {
    api.clearToken();
    setSession(null);
  }

  // --- routing: invite acceptance ---
  if (route.startsWith('/invite/')) {
    const token = route.slice('/invite/'.length);
    return (
      <AcceptInvite
        token={token}
        onAccepted={() => { window.history.pushState({}, '', '/login'); setRoute('/login'); }}
      />
    );
  }

  if (loading) {
    return <div className="login-wrap"><div className="login-card"><p className="sub">Loading…</p></div></div>;
  }

  if (!session) {
    return <Login onAuthenticated={(result) => {
      if (route === '/login') { window.history.pushState({}, '', '/'); setRoute('/'); }
      setSession(result);
      setActiveCard('devices');
    }} />;
  }

  const { orgId, role, orgs, permissions } = session;
  const activeOrg = orgs.find((o) => o.id === orgId);
  const theme = activeOrg?.theme ?? 'cobalt';
  const catalogue = catalogueFrom(permissions);

  // Ensure the active card is visible; if not, pick the first visible one.
  const visibleCards = CARDS.filter((c) => cardVisible(c, permissions));
  const effectiveCard = visibleCards.some((c) => c.key === activeCard)
    ? activeCard
    : (visibleCards[0]?.key ?? 'devices');

  return (
    <div className="app-shell" data-testid="app-shell" data-org-id={orgId} data-org-theme={theme}>
      <div className="topbar">
        <span className="brand">RemoteOps</span>

        <div className="org-switcher">
          {orgs.map((o) => (
            <button
              key={o.id}
              data-testid="org-option"
              data-org-id={o.id}
              aria-current={o.id === orgId ? 'true' : 'false'}
              className="org-option"
              onClick={() => o.id === orgId ? null : handleSwitchOrg(o.id)}
            >
              {o.name}
            </button>
          ))}
          <button data-testid="create-org" className="org-option" onClick={handleCreateOrg}>+ New org</button>
        </div>

        <span className="spacer" />
        <span className="role-badge" data-testid="active-role">{role}</span>
        <button data-testid="sign-out" className="btn ghost small" onClick={handleSignOut}>Sign out</button>
      </div>

      <div className="layout">
        <nav className="nav">
          {CARDS.map((card) => {
            if (!cardVisible(card, permissions)) return null;
            return (
              <button
                key={card.key}
                data-testid={`nav-${card.key}`}
                className={effectiveCard === card.key ? 'active' : ''}
                onClick={() => setActiveCard(card.key)}
              >
                {card.label}
              </button>
            );
          })}
        </nav>

        <main className="content">
          {effectiveCard === 'devices' && <Devices orgId={orgId} orgPermissions={permissions} />}
          {effectiveCard === 'people' && <People orgId={orgId} orgPermissions={permissions} roles={DEFAULT_ROLES} />}
          {effectiveCard === 'grants' && <Grants orgId={orgId} orgPermissions={permissions} catalogue={catalogue} />}
          {effectiveCard === 'sessions' && <Sessions orgId={orgId} orgPermissions={permissions} currentUserId={session.id} />}
          {effectiveCard === 'audit' && <Audit orgId={orgId} />}
          {effectiveCard === 'admin' && (
            <Admin
              orgId={orgId}
              orgName={activeOrg?.name}
              orgPermissions={permissions}
              onOrgChanged={(opts) => { if (opts?.deleted) handleSignOut(); else reloadSession(); }}
            />
          )}
        </main>
      </div>
    </div>
  );
}
