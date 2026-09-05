const ALLOWED_EVENTS = new Set([
  "replay_started",
  "replay_completed",
  "install_copied",
  "github_opened",
  "custom_effect_opened",
]);

interface Env {
  ASSETS: Fetcher;
}

const API_HEADERS = {
  "cache-control": "no-store",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname !== "/api/events") {
      return env.ASSETS.fetch(request);
    }

    if (request.method !== "POST") {
      return new Response(null, {
        status: 405,
        headers: { ...API_HEADERS, allow: "POST" },
      });
    }

    try {
      const payload = (await request.json()) as { event?: unknown };
      if (typeof payload.event !== "string" || !ALLOWED_EVENTS.has(payload.event)) {
        return new Response(null, { status: 400, headers: API_HEADERS });
      }

      // Privacy boundary: record only an allowlisted aggregate event name. Never
      // accept cookies, IDs, URLs, user agents, arbitrary properties, or content.
      console.info(JSON.stringify({ kind: "velvet_site_event", event: payload.event }));
      return new Response(null, { status: 204, headers: API_HEADERS });
    } catch {
      return new Response(null, { status: 400, headers: API_HEADERS });
    }
  },
} satisfies ExportedHandler<Env>;
