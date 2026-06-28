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
//   ASSET_ORIGIN             — base URL for static (build-output) assets (no
//                              trailing slash); the catch-all for non-route URLs
//   UPLOAD_ORIGIN            — base URL for dynamic, user-writable content under
//                              /uploads/* (R490-T8). Reserved seam: no writer
//                              exists yet. Absent → /uploads/* returns 404.
//                              Kept distinct from ASSET_ORIGIN so the publisher's
//                              build-diff purge never treats uploads as stale and
//                              write-auth / cache rules can diverge per prefix.
//   WORKER_MODE              — "static" | "spa" | "ssr"
//   SSR_ORIGIN               — SSR proxy origin URL (empty string for non-SSR modes)
//   SSR_PREFIXES             — JSON-encoded array of path prefixes to proxy to SSR_ORIGIN
//   SSR_RESILIENCE           — JSON-encoded `{ [prefix]: ResiliencePolicy }` (W181 v1);
//                              optional; absent/invalid → no-op (one attempt, no
//                              per-attempt timeout — today's behavior)
//   MESOFACT_BACKEND_ORIGIN  — almanac surface (e.g. http://mesofact-dev:4323);
//                              when set, /api/releases* is proxied here
//   ISSUES_ORIGIN            — issue-tracker surface (e.g. http://mesofact-dev:8731);
//                              when set, /api/issues* is proxied here

interface Env {
  ASSET_ORIGIN: string;
  UPLOAD_ORIGIN?: string;
  WORKER_MODE: string;
  SSR_ORIGIN: string;
  SSR_PREFIXES: string;
  SSR_RESILIENCE?: string;
  MESOFACT_BACKEND_ORIGIN?: string;
  ISSUES_ORIGIN?: string;
}

// W181 v1 schema mirror — see oss/mesofact/packages/mesofact-runtime/src/routes.ts.
// Worker only consumes retry+timeout; queue is rejected upstream at defineRoutes.
type RetryOn = "connection" | "5xx" | "any";
interface RetryPolicy {
  attempts: number;
  backoff_ms: number[];
  retry_on?: RetryOn;
  budget_ms?: number;
}
interface ResiliencePolicy {
  retry?: RetryPolicy;
  timeout_ms?: number;
}
type ResilienceMap = Record<string, ResiliencePolicy>;

const DEFAULT_TIMEOUT_MS = 30_000;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const resilience = parseResilience(env.SSR_RESILIENCE);

    // Backend API routing (R455-T4): /api/issues* → ISSUES_ORIGIN,
    // /api/releases* → MESOFACT_BACKEND_ORIGIN. Takes priority over SSR
    // routing so pond/prod paths hit the backend container directly.
    if (env.ISSUES_ORIGIN && path.startsWith("/api/issues")) {
      const target =
        env.ISSUES_ORIGIN +
        "/issues" +
        path.slice("/api/issues".length) +
        url.search;
      return proxyWithResilience(
        request,
        target,
        policyFor(resilience, path)
      );
    }
    if (env.MESOFACT_BACKEND_ORIGIN && path.startsWith("/api/releases")) {
      const target =
        env.MESOFACT_BACKEND_ORIGIN +
        "/releases" +
        path.slice("/api/releases".length) +
        url.search;
      return proxyWithResilience(
        request,
        target,
        policyFor(resilience, path)
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
      const matched = prefixes.find(
        (p) => path === p || path.startsWith(p.endsWith("/") ? p : p + "/")
      );
      if (matched) {
        const target = env.SSR_ORIGIN + path + url.search;
        return proxyWithResilience(
          request,
          target,
          policyFor(resilience, path)
        );
      }
    }

    // Dynamic user content (R490-T8): /uploads/* routes to UPLOAD_ORIGIN,
    // separate from the build-output static assets on ASSET_ORIGIN. No writer
    // exists yet — the binding is a reserved seam; absent → clean 404, and a
    // miss is a real 404 (never the SPA shell or 404.html, which belong to the
    // static site). Segment-aware: the trailing slash keeps /uploadsfoo out.
    if (path.startsWith("/uploads/")) {
      if (!env.UPLOAD_ORIGIN) {
        return new Response("Not Found", { status: 404 });
      }
      const uploadResp = await fetch(`${env.UPLOAD_ORIGIN}/${path.slice(1)}`);
      if (uploadResp.ok) {
        return uploadResp;
      }
      return new Response("Not Found", { status: 404 });
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

function parseResilience(raw: string | undefined): ResilienceMap {
  if (!raw) return {};
  try {
    const v = JSON.parse(raw);
    return v && typeof v === "object" ? (v as ResilienceMap) : {};
  } catch {
    return {};
  }
}

// W173 segment-aware match: pick the longest matching prefix.
function policyFor(
  map: ResilienceMap,
  path: string
): ResiliencePolicy | undefined {
  let best: { prefix: string; policy: ResiliencePolicy } | undefined;
  for (const [prefix, policy] of Object.entries(map)) {
    const matches =
      path === prefix ||
      path.startsWith(prefix.endsWith("/") ? prefix : prefix + "/");
    if (!matches) continue;
    if (!best || prefix.length > best.prefix.length) {
      best = { prefix, policy };
    }
  }
  return best?.policy;
}

// Proxy `request` to `targetUrl`, applying the route's resilience policy.
// On no policy: one attempt, no per-attempt timeout — today's behavior.
async function proxyWithResilience(
  request: Request,
  targetUrl: string,
  policy: ResiliencePolicy | undefined
): Promise<Response> {
  const method = request.method;
  const hasBody = !["GET", "HEAD"].includes(method);

  // Buffer the body once so retries don't try to re-read a consumed stream.
  // ReadableStreams are one-shot; if we hand the same body to two fetches the
  // second call sees an empty body. Bodies are bounded by Worker request
  // limits (100MB) — buffering in memory is acceptable for retry budgets.
  let bodyBuf: ArrayBuffer | undefined;
  if (hasBody) {
    bodyBuf = await request.arrayBuffer();
  }

  const retry = policy?.retry;
  const attempts = Math.max(1, retry?.attempts ?? 1);
  const backoffMs = retry?.backoff_ms ?? [];
  const retryOn: RetryOn = retry?.retry_on ?? "connection";
  const timeoutMs = policy?.timeout_ms;
  const budgetMs = retry?.budget_ms;
  const start = Date.now();

  let lastErr: unknown;
  let lastResp: Response | undefined;

  for (let attempt = 0; attempt < attempts; attempt++) {
    if (attempt > 0) {
      const gap = backoffMs[attempt - 1] ?? 0;
      if (gap > 0) await sleep(gap);
    }
    if (budgetMs !== undefined && Date.now() - start >= budgetMs) {
      break;
    }
    const init: RequestInit = {
      method,
      headers: request.headers,
      body: hasBody ? bodyBuf : undefined,
      redirect: "follow",
    };
    const controller = timeoutMs !== undefined ? new AbortController() : undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    if (controller) {
      init.signal = controller.signal;
      timer = setTimeout(() => controller.abort(), timeoutMs);
    }
    try {
      const resp = await fetch(targetUrl, init);
      if (timer) clearTimeout(timer);
      // HTTP-level success — return verbatim unless policy retries on 5xx/any.
      if (!shouldRetryOnStatus(resp.status, retryOn)) {
        emitTelemetry(targetUrl, attempt + 1, "ok", Date.now() - start);
        return resp;
      }
      lastResp = resp;
      // Consume body so the connection can be released before retrying.
      try {
        await resp.arrayBuffer();
      } catch {
        // best-effort
      }
    } catch (err) {
      if (timer) clearTimeout(timer);
      lastErr = err;
      if (retryOn !== "connection" && retryOn !== "5xx" && retryOn !== "any") {
        break;
      }
      // Connection-level errors are always retryable when ANY retry policy is
      // declared — `retry_on: "5xx"` still retries connection failures (they
      // strictly subsume the 5xx case).
    }
  }

  const latency = Date.now() - start;
  if (lastResp) {
    emitTelemetry(targetUrl, attempts, "exhausted_5xx", latency);
    return lastResp;
  }
  emitTelemetry(targetUrl, attempts, "exhausted_connection", latency);
  return new Response(
    `upstream unreachable: ${stringifyErr(lastErr)}`,
    { status: 502, headers: { "Content-Type": "text/plain" } }
  );
}

function shouldRetryOnStatus(status: number, retryOn: RetryOn): boolean {
  if (status < 400) return false;
  if (retryOn === "any") return status >= 400;
  if (retryOn === "5xx") return status >= 500;
  return false;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function stringifyErr(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === "string") return e;
  return "unknown error";
}

// W181 v1 telemetry: emit one structured log per request. CF Workers picks up
// console.log; downstream is OTel export, deferred per W181 § "Deferred to v2".
function emitTelemetry(
  target: string,
  attempts: number,
  outcome: "ok" | "exhausted_connection" | "exhausted_5xx",
  latencyMs: number
): void {
  console.log(
    JSON.stringify({
      kind: "mesofact.resilience",
      target,
      attempts,
      outcome,
      latency_ms: latencyMs,
    })
  );
}
