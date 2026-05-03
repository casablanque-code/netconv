/**
 * netconv — Cloudflare Worker
 *
 * Деплой:
 *   1. wasm-pack build crates/netconv-wasm --target bundler --out-dir ../../web/wasm
 *   2. npx wrangler deploy
 *
 * Routes:
 *   GET  /           → index.html (UI)
 *   POST /convert    → JSON API (после подключения WASM)
 *   GET  /health     → 200 OK
 */

import HTML from './index.html';

// После wasm-pack build раскомментировать:
// import init, { convert_config } from './wasm/netconv_wasm.js';
// let wasmReady = false;
// init().then(() => { wasmReady = true; });

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/health') {
      return new Response(JSON.stringify({ ok: true }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (url.pathname === '/convert' && request.method === 'POST') {
      return handleConvert(request);
    }

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    return new Response(HTML, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'public, max-age=3600',
        'X-Content-Type-Options': 'nosniff',
      }
    });
  }
};

async function handleConvert(request) {
  let body;
  try { body = await request.json(); }
  catch { return jsonError('invalid JSON body', 400); }

  const { config, from = 'ios', to = 'vrp' } = body;
  if (!config) return jsonError('"config" required', 400);
  if (config.length > 500_000) return jsonError('too large (max 500KB)', 413);

  // TODO: раскомментировать после wasm-pack build + bundler
  return jsonError('Server-side API coming soon. Используй браузерный UI.', 501);
}

function jsonError(msg, status) {
  return new Response(JSON.stringify({ success: false, error: msg }), {
    status, headers: { 'Content-Type': 'application/json', ...corsHeaders() }
  });
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}
