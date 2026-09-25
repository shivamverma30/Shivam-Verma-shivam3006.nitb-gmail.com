// Route registration. The router is tiny: first match wins, so specific paths must
// be registered before parameterised ones ('/members/me' before '/members/:userId').
//
// Registration order matters for the router's first-match-wins behaviour.

import { registerAuthRoutes } from './auth.js';
import { registerOrgRoutes } from './orgs.js';
import { registerInviteRoutes } from './invites.js';
import { registerDeviceRoutes } from './devices.js';
import { registerSessionRoutes } from './sessions.js';

export function registerRoutes(router, deps) {
  // Auth first (login, refresh, token, me)
  registerAuthRoutes(router, deps);

  // Invites — register public token routes and org-scoped invite routes.
  // Must come before orgs so /orgs/:org/invites is registered, and the
  // public /invites/:token routes are distinct paths.
  registerInviteRoutes(router, deps);

  // Orgs, members, effective, audit.
  // NOTE: orgs.js registers /members/me before /members/:userId internally,
  // which is required for first-match-wins routing.
  registerOrgRoutes(router, deps);

  // Devices and grants
  registerDeviceRoutes(router, deps);

  // Sessions
  registerSessionRoutes(router, deps);
}
