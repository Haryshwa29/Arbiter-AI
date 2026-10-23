// Cloudflare built-ins only; no additional runtime npm dependencies.
import { DurableObject } from "cloudflare:workers";

export class ArbiterDemo extends DurableObject {
  starting;

  async ready() {
    const container = this.ctx.container;
    if (!container.running) {
      container.start({
        image: container.images.base,
        instance: "lite",
        enableInternet: true, // Public demo only: outbound Ollama Cloud inference.
        env: {
          OLLAMA_API_KEY: this.env.OLLAMA_API_KEY,
          ARBITER_SITE_ORIGIN: this.env.PUBLIC_ORIGIN,
        },
      });
    }
    // Allow temporary visitor sessions to survive normal pauses in browsing.
    await container.setInactivityTimeout(30 * 60 * 1000);
    const port = container.getTcpPort(8080);
    for (let attempt = 0; attempt < 50; attempt++) {
      try {
        const response = await port.fetch("http://container/", {signal: AbortSignal.timeout(1000)});
        await response.body?.cancel();
        if (response.ok) return;
      } catch { /* Startup can take several seconds. */ }
      await scheduler.wait(200);
    }
    throw new Error("Demo container is not ready");
  }

  async fetch(request) {
    this.starting ??= this.ready().finally(() => { this.starting = undefined; });
    await this.starting;
    const external = new URL(request.url);
    const forwarded = new Request(`http://container${external.pathname}${external.search}`, request);
    forwarded.headers.set("Host", new URL(this.env.PUBLIC_ORIGIN).host);
    return this.ctx.container.getTcpPort(8080).fetch(forwarded);
  }
}

export default {
  async fetch(request, env) {
    if (!env.PUBLIC_ORIGIN || new URL(request.url).origin !== env.PUBLIC_ORIGIN) {
      return new Response("Use the configured website address.", {status: 403});
    }
    if (!env.OLLAMA_API_KEY) {
      return new Response("The website operator must configure the demo AI key.", {status: 503});
    }
    try {
      // One stable instance keeps cookies, temporary databases and quota aligned.
      return await env.DEMO.getByName("public-demo").fetch(request);
    } catch {
      return new Response("The demo service is starting or unavailable. Please retry.", {status: 503});
    }
  },
};
