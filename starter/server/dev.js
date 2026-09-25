// Cross-platform dev launcher.
//
// The original script used `node --watch-path=./server --watch`, which on some
// platforms (Windows in particular) entered a restart loop: the server opens the
// SQLite database, WAL/SHM sidecar writes land next to it, and the aggressive
// watcher treated those as source changes and restarted endlessly — so the server
// never stayed up long enough to serve a request.
//
// Frontend changes are already hot-reloaded by Vite (middleware mode, wired in
// index.js). This launcher just boots the server once in development mode. If you
// want server-file auto-restart, run:  node --watch-path=./server server/index.js
// once the WAL loop is not a concern on your platform.

process.env.NODE_ENV = process.env.NODE_ENV ?? 'development';
await import('./index.js');
