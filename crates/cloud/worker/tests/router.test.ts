import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { Miniflare } from "miniflare";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const BUNDLE = join(__dirname, "../router.bundle.js");

type Assets = Record<string, { body: string; type: string }>;

interface MfSetup {
  mf: Miniflare;
  port: number;
  stop: () => void;
}

function startAssetServer(assets: Assets): { port: number; stop: () => void } {
  const server = Bun.serve({
    port: 0,
    fetch(req) {
      const key = new URL(req.url).pathname.slice(1) || "index.html";
      const asset = assets[key];
      if (!asset) return new Response("not found", { status: 404 });
      return new Response(asset.body, {
        headers: { "Content-Type": asset.type },
      });
    },
  });
  return { port: server.port, stop: () => server.stop(true) };
}

async function makeMf(cfg: {
  mode: "static" | "spa" | "ssr";
  assets: Assets;
  ssrOrigin?: string;
  ssrPrefixes?: string[];
  mesofactBackendOrigin?: string;
  issuesOrigin?: string;
}): Promise<MfSetup> {
  const { port, stop } = startAssetServer(cfg.assets);
  const bindings: Record<string, string> = {
    ASSET_ORIGIN: `http://localhost:${port}`,
    WORKER_MODE: cfg.mode,
    SSR_ORIGIN: cfg.ssrOrigin ?? "",
    SSR_PREFIXES: JSON.stringify(cfg.ssrPrefixes ?? []),
  };
  if (cfg.mesofactBackendOrigin) {
    bindings.MESOFACT_BACKEND_ORIGIN = cfg.mesofactBackendOrigin;
  }
  if (cfg.issuesOrigin) {
    bindings.ISSUES_ORIGIN = cfg.issuesOrigin;
  }
  const mf = new Miniflare({ modules: true, scriptPath: BUNDLE, bindings });
  return { mf, port, stop };
}

// ── static mode ──────────────────────────────────────────────────────────────

describe("static mode", () => {
  let setup: MfSetup;

  beforeAll(async () => {
    setup = await makeMf({
      mode: "static",
      assets: {
        "index.html": { body: "<h1>hello</h1>", type: "text/html" },
        "app.js": { body: "console.log('hi')", type: "application/javascript" },
        "404.html": { body: "<h1>not found</h1>", type: "text/html" },
      },
    });
  });

  afterAll(async () => {
    await setup.mf.dispose();
    setup.stop();
  });

  test("/ maps to index.html", async () => {
    const resp = await setup.mf.dispatchFetch("http://w.test/");
    expect(resp.status).toBe(200);
    expect(await resp.text()).toContain("hello");
  });

  test("trailing-slash directory resolves to index.html", async () => {
    const resp = await setup.mf.dispatchFetch("http://w.test/subdir/");
    // subdir/index.html not in assets → 404 with 404.html body
    expect(resp.status).toBe(404);
    expect(await resp.text()).toContain("not found");
  });

  test("known asset served directly", async () => {
    const resp = await setup.mf.dispatchFetch("http://w.test/app.js");
    expect(resp.status).toBe(200);
  });

  test("unknown path returns 404 with 404.html body", async () => {
    const resp = await setup.mf.dispatchFetch("http://w.test/nope.html");
    expect(resp.status).toBe(404);
    expect(await resp.text()).toContain("not found");
  });

  test("unknown path returns 404 plain when 404.html absent", async () => {
    // Use a fresh mf without a 404.html asset
    const no404 = await makeMf({ mode: "static", assets: {} });
    const resp = await no404.mf.dispatchFetch("http://w.test/nope");
    expect(resp.status).toBe(404);
    expect(await resp.text()).toBe("Not Found");
    await no404.mf.dispose();
    no404.stop();
  });
});

// ── SPA mode ─────────────────────────────────────────────────────────────────

describe("spa mode", () => {
  let setup: MfSetup;

  beforeAll(async () => {
    setup = await makeMf({
      mode: "spa",
      assets: {
        "index.html": { body: "<h1>spa shell</h1>", type: "text/html" },
        "app.js": { body: "console.log('spa')", type: "application/javascript" },
      },
    });
  });

  afterAll(async () => {
    await setup.mf.dispose();
    setup.stop();
  });

  test("/ serves index.html", async () => {
    const resp = await setup.mf.dispatchFetch("http://w.test/");
    expect(resp.status).toBe(200);
    expect(await resp.text()).toContain("spa shell");
  });

  test("unknown deep path falls back to index.html (client-side routing)", async () => {
    const resp = await setup.mf.dispatchFetch("http://w.test/deep/route");
    expect(resp.status).toBe(200);
    expect(await resp.text()).toContain("spa shell");
  });

  test("known asset served directly without fallback", async () => {
    const resp = await setup.mf.dispatchFetch("http://w.test/app.js");
    expect(resp.status).toBe(200);
  });
});

// ── SSR mode ──────────────────────────────────────────────────────────────────

describe("ssr mode", () => {
  let setup: MfSetup;
  let ssrPort: number;
  let stopSsr: () => void;

  beforeAll(async () => {
    const ssr = Bun.serve({
      port: 0,
      fetch(req) {
        const path = new URL(req.url).pathname;
        return new Response(`ssr:${path}`, { status: 200 });
      },
    });
    ssrPort = ssr.port;
    stopSsr = () => ssr.stop(true);

    setup = await makeMf({
      mode: "ssr",
      assets: {
        "index.html": { body: "<h1>ssr shell</h1>", type: "text/html" },
      },
      ssrOrigin: `http://localhost:${ssrPort}`,
      ssrPrefixes: ["/api/", "/rpc/"],
    });
  });

  afterAll(async () => {
    await setup.mf.dispose();
    setup.stop();
    stopSsr();
  });

  test("/api/ prefix proxied to SSR origin", async () => {
    const resp = await setup.mf.dispatchFetch("http://w.test/api/data");
    expect(resp.status).toBe(200);
    expect(await resp.text()).toBe("ssr:/api/data");
  });

  test("/rpc/ prefix proxied to SSR origin", async () => {
    const resp = await setup.mf.dispatchFetch("http://w.test/rpc/call");
    expect(resp.status).toBe(200);
    expect(await resp.text()).toBe("ssr:/rpc/call");
  });

  test("non-prefixed paths fall back to index.html shell", async () => {
    const resp = await setup.mf.dispatchFetch("http://w.test/some-page");
    expect(resp.status).toBe(200);
    expect(await resp.text()).toContain("ssr shell");
  });
});

// ── SSR matcher: W173 segment-aware boundary ─────────────────────────────────

describe("ssr segment-aware matcher (W173)", () => {
  let setup: MfSetup;
  let ssrPort: number;
  let stopSsr: () => void;

  beforeAll(async () => {
    const ssr = Bun.serve({
      port: 0,
      fetch(req) {
        const path = new URL(req.url).pathname;
        return new Response(`ssr:${path}`, { status: 200 });
      },
    });
    ssrPort = ssr.port;
    stopSsr = () => ssr.stop(true);

    setup = await makeMf({
      mode: "ssr",
      assets: {
        "index.html": { body: "<h1>shell</h1>", type: "text/html" },
        "api/healthcheck.html": { body: "<p>sibling</p>", type: "text/html" },
      },
      ssrOrigin: `http://localhost:${ssrPort}`,
      // Non-parametric prefix derived from /api/health route per W173.
      ssrPrefixes: ["/api/health"],
    });
  });

  afterAll(async () => {
    await setup.mf.dispose();
    setup.stop();
    stopSsr();
  });

  test("/api/health matches exactly and proxies to SSR origin", async () => {
    const resp = await setup.mf.dispatchFetch("http://w.test/api/health");
    expect(resp.status).toBe(200);
    expect(await resp.text()).toBe("ssr:/api/health");
  });

  test("/api/health/sub matches descendant segment and proxies", async () => {
    const resp = await setup.mf.dispatchFetch("http://w.test/api/health/sub");
    expect(resp.status).toBe(200);
    expect(await resp.text()).toBe("ssr:/api/health/sub");
  });

  test("/api/healthcheck does NOT proxy (segment boundary)", async () => {
    const resp = await setup.mf.dispatchFetch("http://w.test/api/healthcheck");
    // Falls through to asset serving — neither /api/healthcheck nor
    // /api/healthcheck.html prefix-matches "/api/health" segment-wise.
    // (The asset key here is api/healthcheck which is absent; fallback to shell.)
    expect(await resp.text()).not.toContain("ssr:");
  });
});

describe("ssr matcher with trailing-slash prefix (parametric route)", () => {
  let setup: MfSetup;
  let ssrPort: number;
  let stopSsr: () => void;

  beforeAll(async () => {
    const ssr = Bun.serve({
      port: 0,
      fetch(req) {
        const path = new URL(req.url).pathname;
        return new Response(`ssr:${path}`, { status: 200 });
      },
    });
    ssrPort = ssr.port;
    stopSsr = () => ssr.stop(true);

    setup = await makeMf({
      mode: "ssr",
      assets: { "index.html": { body: "<h1>shell</h1>", type: "text/html" } },
      ssrOrigin: `http://localhost:${ssrPort}`,
      // Trailing-slash prefix derived from /api/users/:id per W173.
      ssrPrefixes: ["/api/users/"],
    });
  });

  afterAll(async () => {
    await setup.mf.dispose();
    setup.stop();
    stopSsr();
  });

  test("/api/users/42 proxies to origin", async () => {
    const resp = await setup.mf.dispatchFetch("http://w.test/api/users/42");
    expect(resp.status).toBe(200);
    expect(await resp.text()).toBe("ssr:/api/users/42");
  });

  test("/api/usersx does NOT proxy (trailing slash boundary)", async () => {
    const resp = await setup.mf.dispatchFetch("http://w.test/api/usersx");
    expect(await resp.text()).not.toContain("ssr:");
  });
});

// ── backend API routing (R455-T4) ────────────────────────────────────────────

describe("backend API routing — ISSUES_ORIGIN", () => {
  let setup: MfSetup;
  let issuesPort: number;
  let stopIssues: () => void;

  beforeAll(async () => {
    const issues = Bun.serve({
      port: 0,
      fetch(req) {
        const path = new URL(req.url).pathname;
        return new Response(`issues:${req.method}:${path}`, { status: 201 });
      },
    });
    issuesPort = issues.port;
    stopIssues = () => issues.stop(true);

    setup = await makeMf({
      mode: "static",
      assets: { "index.html": { body: "<h1>home</h1>", type: "text/html" } },
      issuesOrigin: `http://localhost:${issuesPort}`,
    });
  });

  afterAll(async () => {
    await setup.mf.dispose();
    setup.stop();
    stopIssues();
  });

  test("POST /api/issues proxied to ISSUES_ORIGIN/issues", async () => {
    const resp = await setup.mf.dispatchFetch("http://w.test/api/issues", {
      method: "POST",
      body: JSON.stringify({ title: "test" }),
      headers: { "Content-Type": "application/json" },
    });
    expect(resp.status).toBe(201);
    expect(await resp.text()).toBe("issues:POST:/issues");
  });

  test("GET /api/issues/123 proxied to ISSUES_ORIGIN/issues/123", async () => {
    const resp = await setup.mf.dispatchFetch("http://w.test/api/issues/123");
    expect(resp.status).toBe(201);
    expect(await resp.text()).toBe("issues:GET:/issues/123");
  });

  test("/api/issues routing absent when ISSUES_ORIGIN not set", async () => {
    const noBackend = await makeMf({
      mode: "static",
      assets: { "index.html": { body: "<h1>home</h1>", type: "text/html" } },
    });
    const resp = await noBackend.mf.dispatchFetch("http://w.test/api/issues", {
      method: "POST",
      body: "{}",
      headers: { "Content-Type": "application/json" },
    });
    // Falls through to asset origin (key = api/issues → 404 from asset server)
    expect(resp.status).not.toBe(201);
    await noBackend.mf.dispose();
    noBackend.stop();
  });
});

describe("backend API routing — MESOFACT_BACKEND_ORIGIN", () => {
  let setup: MfSetup;
  let backendPort: number;
  let stopBackend: () => void;

  beforeAll(async () => {
    const backend = Bun.serve({
      port: 0,
      fetch(req) {
        const path = new URL(req.url).pathname;
        return new Response(`backend:${req.method}:${path}`, { status: 200 });
      },
    });
    backendPort = backend.port;
    stopBackend = () => backend.stop(true);

    setup = await makeMf({
      mode: "static",
      assets: { "index.html": { body: "<h1>home</h1>", type: "text/html" } },
      mesofactBackendOrigin: `http://localhost:${backendPort}`,
    });
  });

  afterAll(async () => {
    await setup.mf.dispose();
    setup.stop();
    stopBackend();
  });

  test("GET /api/releases proxied to MESOFACT_BACKEND_ORIGIN/releases", async () => {
    const resp = await setup.mf.dispatchFetch("http://w.test/api/releases");
    expect(resp.status).toBe(200);
    expect(await resp.text()).toBe("backend:GET:/releases");
  });

  test("GET /api/releases/v1.2.3 proxied with sub-path", async () => {
    const resp = await setup.mf.dispatchFetch("http://w.test/api/releases/v1.2.3");
    expect(resp.status).toBe(200);
    expect(await resp.text()).toBe("backend:GET:/releases/v1.2.3");
  });

  test("ISSUES_ORIGIN takes priority over SSR for /api/issues", async () => {
    const ssr = Bun.serve({
      port: 0,
      fetch(req) {
        return new Response("ssr-hit", { status: 200 });
      },
    });
    const mixedSetup = await makeMf({
      mode: "ssr",
      assets: { "index.html": { body: "<h1>shell</h1>", type: "text/html" } },
      ssrOrigin: `http://localhost:${ssr.port}`,
      ssrPrefixes: ["/api/issues"],
      issuesOrigin: `http://localhost:${backendPort}`,
    });
    const resp = await mixedSetup.mf.dispatchFetch("http://w.test/api/issues", {
      method: "POST",
      body: "{}",
      headers: { "Content-Type": "application/json" },
    });
    // Backend routing wins over SSR prefix routing.
    const body = await resp.text();
    expect(body).not.toContain("ssr-hit");
    expect(body).toContain("backend:POST:");
    await mixedSetup.mf.dispose();
    mixedSetup.stop();
    ssr.stop(true);
  });
});
