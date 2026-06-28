// router.ts
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
var router_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const resilience = parseResilience(env.SSR_RESILIENCE);
    if (env.ISSUES_ORIGIN && path.startsWith("/api/issues")) {
      const target = env.ISSUES_ORIGIN + "/issues" + path.slice("/api/issues".length) + url.search;
      return proxyWithResilience(request, target, policyFor(resilience, path));
    }
    if (env.MESOFACT_BACKEND_ORIGIN && path.startsWith("/api/releases")) {
      const target = env.MESOFACT_BACKEND_ORIGIN + "/releases" + path.slice("/api/releases".length) + url.search;
      return proxyWithResilience(request, target, policyFor(resilience, path));
    }
    if (env.WORKER_MODE === "ssr" && env.SSR_ORIGIN) {
      let prefixes = [];
      try {
        prefixes = JSON.parse(env.SSR_PREFIXES);
      } catch {}
      const matched = prefixes.find((p) => path === p || path.startsWith(p.endsWith("/") ? p : p + "/"));
      if (matched) {
        const target = env.SSR_ORIGIN + path + url.search;
        return proxyWithResilience(request, target, policyFor(resilience, path));
      }
    }
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
    let key;
    if (path === "/" || path.endsWith("/")) {
      key = (path === "/" ? "" : path.slice(1)) + "index.html";
    } else {
      key = path.slice(1);
    }
    const assetResp = await fetch(`${env.ASSET_ORIGIN}/${key}`);
    if (assetResp.ok) {
      return assetResp;
    }
    if (env.WORKER_MODE === "static") {
      const notFoundResp = await fetch(`${env.ASSET_ORIGIN}/404.html`);
      if (notFoundResp.ok) {
        return new Response(notFoundResp.body, {
          status: 404,
          headers: notFoundResp.headers
        });
      }
      return new Response("Not Found", { status: 404 });
    } else {
      const shellResp = await fetch(`${env.ASSET_ORIGIN}/index.html`);
      if (shellResp.ok) {
        return new Response(shellResp.body, {
          status: 200,
          headers: shellResp.headers
        });
      }
      return new Response("Not Found", { status: 404 });
    }
  }
};
function parseResilience(raw) {
  if (!raw)
    return {};
  try {
    const v = JSON.parse(raw);
    return v && typeof v === "object" ? v : {};
  } catch {
    return {};
  }
}
function policyFor(map, path) {
  let best;
  for (const [prefix, policy] of Object.entries(map)) {
    const matches = path === prefix || path.startsWith(prefix.endsWith("/") ? prefix : prefix + "/");
    if (!matches)
      continue;
    if (!best || prefix.length > best.prefix.length) {
      best = { prefix, policy };
    }
  }
  return best?.policy;
}
async function proxyWithResilience(request, targetUrl, policy) {
  const method = request.method;
  const hasBody = !["GET", "HEAD"].includes(method);
  let bodyBuf;
  if (hasBody) {
    bodyBuf = await request.arrayBuffer();
  }
  const retry = policy?.retry;
  const attempts = Math.max(1, retry?.attempts ?? 1);
  const backoffMs = retry?.backoff_ms ?? [];
  const retryOn = retry?.retry_on ?? "connection";
  const timeoutMs = policy?.timeout_ms;
  const budgetMs = retry?.budget_ms;
  const start = Date.now();
  let lastErr;
  let lastResp;
  for (let attempt = 0;attempt < attempts; attempt++) {
    if (attempt > 0) {
      const gap = backoffMs[attempt - 1] ?? 0;
      if (gap > 0)
        await sleep(gap);
    }
    if (budgetMs !== undefined && Date.now() - start >= budgetMs) {
      break;
    }
    const init = {
      method,
      headers: request.headers,
      body: hasBody ? bodyBuf : undefined,
      redirect: "follow"
    };
    const controller = timeoutMs !== undefined ? new AbortController : undefined;
    let timer;
    if (controller) {
      init.signal = controller.signal;
      timer = setTimeout(() => controller.abort(), timeoutMs);
    }
    try {
      const resp = await fetch(targetUrl, init);
      if (timer)
        clearTimeout(timer);
      if (!shouldRetryOnStatus(resp.status, retryOn)) {
        emitTelemetry(targetUrl, attempt + 1, "ok", Date.now() - start);
        return resp;
      }
      lastResp = resp;
      try {
        await resp.arrayBuffer();
      } catch {}
    } catch (err) {
      if (timer)
        clearTimeout(timer);
      lastErr = err;
      if (retryOn !== "connection" && retryOn !== "5xx" && retryOn !== "any") {
        break;
      }
    }
  }
  const latency = Date.now() - start;
  if (lastResp) {
    emitTelemetry(targetUrl, attempts, "exhausted_5xx", latency);
    return lastResp;
  }
  emitTelemetry(targetUrl, attempts, "exhausted_connection", latency);
  return new Response(`upstream unreachable: ${stringifyErr(lastErr)}`, { status: 502, headers: { "Content-Type": "text/plain" } });
}
function shouldRetryOnStatus(status, retryOn) {
  if (status < 400)
    return false;
  if (retryOn === "any")
    return status >= 400;
  if (retryOn === "5xx")
    return status >= 500;
  return false;
}
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
function stringifyErr(e) {
  if (e instanceof Error)
    return e.message;
  if (typeof e === "string")
    return e;
  return "unknown error";
}
function emitTelemetry(target, attempts, outcome, latencyMs) {
  console.log(JSON.stringify({
    kind: "mesofact.resilience",
    target,
    attempts,
    outcome,
    latency_ms: latencyMs
  }));
}
export {
  router_default as default
};
