// Cross-platform db:reset. Removes the SQLite files (and WAL/SHM sidecars) then
// runs the loader. Replaces the Unix-only `rm -f ... && npm run db:load`, which
// failed on Windows PowerShell.

import { rmSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const DB_FILE = process.env.DATABASE_FILE ?? 'app.db';
for (const suffix of ['', '-wal', '-shm']) {
  const f = DB_FILE + suffix;
  if (existsSync(f)) rmSync(f);
}

const loader = fileURLToPath(new URL('./load-db.js', import.meta.url));
const result = spawnSync(process.execPath, [loader], { stdio: 'inherit' });
process.exit(result.status ?? 0);
