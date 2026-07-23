// src/manifest.ts
async function loadManifest(assetOrigin) {
  try {
    const resp = await fetch(`${assetOrigin}/manifest.json`);
    if (!resp.ok) {
      return null;
    }
    return await resp.json();
  } catch {
    return null;
  }
}
function matchesDeferredRoute(manifest, pathname) {
  if (!manifest?.routes) {
    return false;
  }
  return manifest.routes.some((r) => isDeferred(r) && matchRoutePattern(r.route, pathname));
}
function isDeferred(route) {
  const p = route.prerender;
  return !!p && p.deferred === true;
}
function matchRoutePattern(pattern, pathname) {
  const pat = splitSegments(pattern);
  const path = splitSegments(pathname);
  if (pat.length !== path.length) {
    return false;
  }
  for (let i = 0;i < pat.length; i++) {
    const seg = pat[i];
    if (seg.startsWith(":")) {
      if (path[i].length === 0) {
        return false;
      }
    } else if (seg !== path[i]) {
      return false;
    }
  }
  return true;
}
function splitSegments(p) {
  return p.split("/").filter((s) => s.length > 0);
}

// src/pointer.ts
var POINTER_PREFIX = "p/";
var POINTER_RECORD_V = 1;

class PointerMalformed extends Error {
}
function validateKey(key) {
  if (key.length === 0) {
    return "empty key is reserved for the site root pointer";
  }
  if (key.startsWith("/") || key.endsWith("/")) {
    return "leading/trailing slash";
  }
  for (const seg of key.split("/")) {
    if (seg === "" || seg === "." || seg === "..") {
      return "empty or dot path segment";
    }
  }
  if (/[\s\x00-\x1f\x7f]/.test(key)) {
    return "control or whitespace character";
  }
  return null;
}
async function resolvePointer(pointerOrigin, key) {
  if (validateKey(key) !== null) {
    return { kind: "absent" };
  }
  const url = `${pointerOrigin}/${POINTER_PREFIX}${key}`;
  const resp = await fetch(url);
  if (resp.status === 404) {
    return { kind: "absent" };
  }
  if (!resp.ok) {
    throw new PointerMalformed(`pointer read ${url} -> ${resp.status}`);
  }
  let record;
  try {
    record = await resp.json();
  } catch {
    throw new PointerMalformed(`pointer ${key}: malformed JSON`);
  }
  if (record.v !== POINTER_RECORD_V) {
    throw new PointerMalformed(`pointer ${key}: record version ${record.v} (edge speaks ${POINTER_RECORD_V})`);
  }
  return record.pointer ? { kind: "present", pointer: record.pointer } : { kind: "deleted" };
}

// src/router.ts
var IMMUTABLE_CACHE_CONTROL = "public, max-age=31536000, immutable";
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
    const manifest = await loadManifest(env.ASSET_ORIGIN);
    if (matchesDeferredRoute(manifest, path)) {
      return serveInstance(env, path, manifest);
    }
    const lastSegment = key.slice(key.lastIndexOf("/") + 1);
    if (!lastSegment.includes(".")) {
      for (const candidate of [`${key}.html`, `${key}/index.html`]) {
        const cleanResp = await fetch(`${env.ASSET_ORIGIN}/${candidate}`);
        if (cleanResp.ok) {
          return cleanResp;
        }
      }
    }
    if (env.WORKER_MODE === "static") {
      return errorResponse(404, env.ASSET_ORIGIN, manifest?.error_routes);
    }
    const shellResp = await fetch(`${env.ASSET_ORIGIN}/index.html`);
    if (shellResp.ok) {
      return new Response(shellResp.body, {
        status: 200,
        headers: shellResp.headers
      });
    }
    return errorResponse(404, env.ASSET_ORIGIN, manifest?.error_routes);
  }
};
async function serveInstance(env, path, manifest) {
  const pointerOrigin = env.POINTER_ORIGIN || env.ASSET_ORIGIN;
  const key = path.slice(1);
  let state;
  try {
    state = await resolvePointer(pointerOrigin, key);
  } catch (err) {
    if (err instanceof PointerMalformed) {
      return errorResponse(500, env.ASSET_ORIGIN, manifest?.error_routes);
    }
    throw err;
  }
  if (state.kind === "present") {
    const contentResp = await fetch(`${env.ASSET_ORIGIN}/${state.pointer.content_root}`);
    if (!contentResp.ok) {
      return errorResponse(404, env.ASSET_ORIGIN, manifest?.error_routes);
    }
    const headers = new Headers(contentResp.headers);
    headers.set("Cache-Control", IMMUTABLE_CACHE_CONTROL);
    return new Response(contentResp.body, { status: 200, headers });
  }
  if (state.kind === "deleted") {
    return errorResponse(410, env.ASSET_ORIGIN, manifest?.error_routes, "410 Gone");
  }
  return errorResponse(404, env.ASSET_ORIGIN, manifest?.error_routes);
}
async function errorResponse(status, assetOrigin, errorRoutes, fallbackText) {
  const brandedRoute = status >= 500 ? errorRoutes?.["5xx"] : errorRoutes?.["404"];
  const keys = [];
  if (brandedRoute)
    keys.push(...routeToAssetKeys(brandedRoute));
  if (status < 500)
    keys.push("404.html");
  for (const k of keys) {
    const resp = await fetch(`${assetOrigin}/${k}`);
    if (resp.ok) {
      return new Response(resp.body, { status, headers: resp.headers });
    }
  }
  return new Response(fallbackText ?? defaultStatusText(status), { status });
}
function routeToAssetKeys(routePath) {
  const rel = routePath.replace(/^\/+/, "");
  if (rel === "")
    return ["index.html"];
  const last = rel.split("/").pop() ?? "";
  if (last.includes("."))
    return [rel];
  return [rel, `${rel}.html`, `${rel}/index.html`];
}
function defaultStatusText(status) {
  if (status === 410)
    return "Gone";
  if (status >= 500)
    return "Internal Server Error";
  return "Not Found";
}
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
  return new Response(`upstream unreachable: ${stringifyErr(lastErr)}`, {
    status: 502,
    headers: { "Content-Type": "text/plain" }
  });
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
