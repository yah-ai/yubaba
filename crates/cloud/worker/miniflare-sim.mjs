// miniflare-sim.mjs — yah local-sim edge-fidelity layer.
// Runs the Worker script under miniflare v3 (workerd subprocess).
// Spawned by yah's local_sim reconciler; config via environment variables:
//
//   MF_PORT             — listen port (default: 4322)
//   MF_HOST             — bind address (default: 127.0.0.1; set 0.0.0.0 when
//                         running inside a container so the published port
//                         is reachable from the host)
//   MF_SCRIPT           — absolute path to the Worker JS file (required)
//   MF_MINIFLARE_IMPORT — absolute path to miniflare's CJS index.js; allows
//                         resolving miniflare when its node_modules lives
//                         outside this file's ancestor directories
//   ASSET_ORIGIN        — base URL for static assets, no trailing slash
//                         (e.g. http://minio:9000/yah-dev for bridge MinIO,
//                         or http://127.0.0.1:9000/yah-dev legacy)
//   WORKER_MODE         — "static" | "spa" | "ssr"
//   SSR_ORIGIN          — SSR proxy origin (empty string for non-SSR modes)
//   SSR_PREFIXES        — JSON array of SSR path prefixes (default: "[]")

import { readFileSync } from 'fs';

const port = parseInt(process.env.MF_PORT ?? '4322', 10);
const host = process.env.MF_HOST ?? '127.0.0.1';
const scriptPath = process.env.MF_SCRIPT;
const assetOrigin = process.env.ASSET_ORIGIN ?? '';
const workerMode = process.env.WORKER_MODE ?? 'static';
const ssrOrigin = process.env.SSR_ORIGIN ?? '';
const ssrPrefixes = process.env.SSR_PREFIXES ?? '[]';

if (!scriptPath) {
  process.stderr.write('[miniflare-sim] MF_SCRIPT env var is required\n');
  process.exit(1);
}

const script = readFileSync(scriptPath, 'utf-8');

// Dynamic import lets us load miniflare from an absolute path when it lives
// outside this file's node_modules ancestor chain (the common case when yah
// writes this shim to a state dir but miniflare is installed in the monorepo
// worker directory).
const miniflareImport = process.env.MF_MINIFLARE_IMPORT ?? 'miniflare';
const { Miniflare } = await import(miniflareImport);

const mf = new Miniflare({
  port,
  host,
  // Pass script content rather than scriptPath to avoid workerd's path
  // canonicalization check (which rejects absolute paths on some platforms).
  script,
  modules: true,
  bindings: {
    ASSET_ORIGIN: assetOrigin,
    WORKER_MODE: workerMode,
    SSR_ORIGIN: ssrOrigin,
    SSR_PREFIXES: ssrPrefixes,
  },
});

const url = await mf.ready;
process.stdout.write(`[miniflare-sim] ready on ${url}\n`);

process.on('SIGTERM', async () => {
  await mf.dispose().catch(() => {});
  process.exit(0);
});
process.on('SIGINT', async () => {
  await mf.dispose().catch(() => {});
  process.exit(0);
});
