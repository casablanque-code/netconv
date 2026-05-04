/**
 * netconv — Cloudflare Worker
 *
 * Cloudflare Assets обслуживает всю статику из web/:
 *   GET /              → index.html
 *   GET /wasm/*.js     → WASM JS биндинги
 *   GET /wasm/*.wasm   → WASM бинарник
 *
 * Worker перехватывает только:
 *   POST /convert      → JSON API (будущее)
 *   GET  /health       → healthcheck
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Health check
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({ ok: true, version: '0.1.0' }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // API endpoint (будущее — серверная конвертация через WASM)
    if (url.pathname === '/convert' && request.method === 'POST') {
      return handleConvert(request);
    }

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    // Всё остальное — отдаём через CF Assets (index.html, wasm/*, etc.)
    return env.ASSETS.fetch(request);
  }
};

async function handleConvert(request) {
  let body;
  try { body = await request.json(); }
  catch { return jsonError('invalid JSON body', 400); }

  const { config, from = 'ios', to = 'vrp' } = body;
  if (!config) return jsonError('"config" required', 400);
  if (config.length > 500_000) return jsonError('too large (max 500KB)', 413);

  // Конвертация происходит в браузере (WASM).
  // Серверный endpoint — для будущей CLI/API интеграции.
  return jsonError('Use browser UI for conversion. Server-side API coming soon.', 501);
}

function jsonError(msg, status) {
  return new Response(JSON.stringify({ success: false, error: msg }), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders() }
  });
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}
