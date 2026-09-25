// Cross-platform production launcher. Sets NODE_ENV=production (the Unix-only
// `NODE_ENV=production node ...` form fails on Windows PowerShell) then boots the
// server. Serves the built SPA from dist/, so run `npm run build` first.

process.env.NODE_ENV = 'production';
await import('./index.js');
