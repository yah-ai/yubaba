// router.ts — generated bundle; annotations live in router.ts
var router_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (env.ISSUES_ORIGIN && path.startsWith("/api/issues")) {
      return fetch(new Request(env.ISSUES_ORIGIN + "/issues" + path.slice("/api/issues".length) + url.search, {
        method: request.method,
        headers: request.headers,
        body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
        redirect: "follow"
      }));
    }
    if (env.MESOFACT_BACKEND_ORIGIN && path.startsWith("/api/releases")) {
      return fetch(new Request(env.MESOFACT_BACKEND_ORIGIN + "/releases" + path.slice("/api/releases".length) + url.search, {
        method: request.method,
        headers: request.headers,
        body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
        redirect: "follow"
      }));
    }
    if (env.WORKER_MODE === "ssr" && env.SSR_ORIGIN) {
      let prefixes = [];
      try {
        prefixes = JSON.parse(env.SSR_PREFIXES);
      } catch {}
      const matches = prefixes.some((p) => path === p || path.startsWith(p.endsWith("/") ? p : p + "/"));
      if (matches) {
        return fetch(new Request(env.SSR_ORIGIN + path + url.search, {
          method: request.method,
          headers: request.headers,
          body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
          redirect: "follow"
        }));
      }
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
export {
  router_default as default
};
