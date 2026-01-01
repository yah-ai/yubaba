//! @yah:ticket(R369-F1, "CI guard router.bundle.js matches router.ts rebuild")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-01T03:27:09Z)
//! @yah:status(review)
//! @yah:parent(R369)
//! @yah:next("router.bundle.js is checked in and shipped to Cloudflare on each deploy, but router.ts is the source. If a contributor edits router.ts without running `bun run build`, prod ships stale code. The bundle hasn't been rebuilt recently per git log")
//! @yah:next("Add a CI step (or pre-commit hook) that runs `bun run build` in crates/yah/cloud/worker/ and fails if the resulting router.bundle.js differs from the committed file. Alternatively, stop committing the bundle and build it in the deploy step. Pick one — committed-bundle-with-CI-guard is simpler")
//! @yah:next("Worker tests at crates/yah/cloud/worker/tests/router.test.ts already exist (R327-F1) — make sure they run in CI alongside this guard")
//! @yah:verify("CI fails on a PR that edits router.ts without re-running the build")
//! @yah:verify("CI passes on a PR that edits both router.ts and router.bundle.js consistently")
//!
//! @yah:ticket(R455-T4, "Worker MESOFACT_BACKEND_ORIGIN + ISSUES_ORIGIN bindings; route /api/* through Worker")
//! @yah:at(2026-06-05T08:24:46Z)
//! @yah:status(review)
//! @yah:phase(D)
//! @yah:parent(R455)
//! @yah:next("Worker env bindings injected through MiniflareSpec extra_env: MESOFACT_BACKEND_ORIGIN=http://mesofact-dev:4323, ISSUES_ORIGIN=http://mesofact-dev:8731")
//! @yah:next("Worker router: forward /api/issues* to ISSUES_ORIGIN; /api/releases* (and future feed endpoints) to MESOFACT_BACKEND_ORIGIN")
//! @yah:next("Marketing SSR handlers in app/yah/web/marketing/mesofact.routes.ts swap their direct fetches for Worker-routed paths so the prod CF path stays identical")
//! @yah:verify("Pond up against yah-marketing: POST /api/issues round-trips through the Worker to mesofact-dev's issue-tracker")
//! @yah:verify("GET /api/releases returns the almanac feed instead of 404")
//! @arch:see(.yah/docs/working/W180-pond-richer-topology.md)
//! @yah:depends_on(R455-F3)

// Worker router for mesofact-static sites.
// Config injected via plain_text Worker bindings:
//   ASSET_ORIGIN             — base URL for static assets (no trailing slash)
//   WORKER_MODE              — "static" | "spa" | "ssr"
//   SSR_ORIGIN               — SSR proxy origin URL (empty string for non-SSR modes)
//   SSR_PREFIXES             — JSON-encoded array of path prefixes to proxy to SSR_ORIGIN
//   MESOFACT_BACKEND_ORIGIN  — almanac surface (e.g. http://mesofact-dev:4323);
//                              when set, /api/releases* is proxied here
//   ISSUES_ORIGIN            — issue-tracker surface (e.g. http://mesofact-dev:8731);
//                              when set, /api/issues* is proxied here

interface Env {
  ASSET_ORIGIN: string;
  WORKER_MODE: string;
  SSR_ORIGIN: string;
  SSR_PREFIXES: string;
  MESOFACT_BACKEND_ORIGIN?: string;
  ISSUES_ORIGIN?: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // Backend API routing (R455-T4): /api/issues* → ISSUES_ORIGIN,
    // /api/releases* → MESOFACT_BACKEND_ORIGIN. Takes priority over SSR
    // routing so pond/prod paths hit the backend container directly.
    if (env.ISSUES_ORIGIN && path.startsWith("/api/issues")) {
      return fetch(
        new Request(env.ISSUES_ORIGIN + "/issues" + path.slice("/api/issues".length) + url.search, {
          method: request.method,
          headers: request.headers,
          body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
          redirect: "follow",
        })
      );
    }
    if (env.MESOFACT_BACKEND_ORIGIN && path.startsWith("/api/releases")) {
      return fetch(
        new Request(env.MESOFACT_BACKEND_ORIGIN + "/releases" + path.slice("/api/releases".length) + url.search, {
          method: request.method,
          headers: request.headers,
          body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
          redirect: "follow",
        })
      );
    }

    // SSR: proxy matching prefixes to origin
    if (env.WORKER_MODE === "ssr" && env.SSR_ORIGIN) {
      let prefixes: string[] = [];
      try {
        prefixes = JSON.parse(env.SSR_PREFIXES);
      } catch {
        // malformed JSON — fall through to asset serving
      }
      // Segment-aware match (W173): exact prefix OR descendant under prefix.
      // Naive `path.startsWith(p)` would proxy /api/healthcheck to an
      // /api/health origin — bytes match, segments don't.
      const matches = prefixes.some(
        (p) => path === p || path.startsWith(p.endsWith("/") ? p : p + "/")
      );
      if (matches) {
        return fetch(
          new Request(env.SSR_ORIGIN + path + url.search, {
            method: request.method,
            headers: request.headers,
            body: ["GET", "HEAD"].includes(request.method)
              ? undefined
              : request.body,
            redirect: "follow",
          })
        );
      }
    }

    // Resolve asset key from URL path
    let key: string;
    if (path === "/" || path.endsWith("/")) {
      key = (path === "/" ? "" : path.slice(1)) + "index.html";
    } else {
      key = path.slice(1);
    }

    // Fetch from asset origin
    const assetResp = await fetch(`${env.ASSET_ORIGIN}/${key}`);
    if (assetResp.ok) {
      return assetResp;
    }

    // Fallback: static → 404.html or plain 404; SPA/SSR → index.html shell
    if (env.WORKER_MODE === "static") {
      const notFoundResp = await fetch(`${env.ASSET_ORIGIN}/404.html`);
      if (notFoundResp.ok) {
        return new Response(notFoundResp.body, {
          status: 404,
          headers: notFoundResp.headers,
        });
      }
      return new Response("Not Found", { status: 404 });
    } else {
      const shellResp = await fetch(`${env.ASSET_ORIGIN}/index.html`);
      if (shellResp.ok) {
        return new Response(shellResp.body, {
          status: 200,
          headers: shellResp.headers,
        });
      }
      return new Response("Not Found", { status: 404 });
    }
  },
};
