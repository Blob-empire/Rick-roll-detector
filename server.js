/**
 * PrivateRoute Mini — single-file privacy proxy
 * Two files: server.js + package.json. Deploy to Render as-is.
 */

import http from 'http';
import https from 'https';
import { URL } from 'url';
import crypto from 'crypto';

const PORT = parseInt(process.env.PORT || '3000', 10);
const ACCESS_TOKEN = process.env.ACCESS_TOKEN || '';
const SESSION_TTL_MS = parseInt(process.env.SESSION_TTL_MS || String(30 * 60 * 1000), 10);

// ── SSRF blocklist ────────────────────────────────────────────────────────────
const BLOCKED_HOSTS = new Set(['localhost', '0.0.0.0', '::1', 'metadata.google.internal']);
const BLOCKED_IP = [
  /^127\./, /^10\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./,
  /^169\.254\./, /^0\./, /^::1$/, /^fc/i, /^fd/i, /^fe80/i,
];

function isBlockedHost(h) {
  if (BLOCKED_HOSTS.has(h.toLowerCase())) return true;
  return BLOCKED_IP.some(r => r.test(h));
}

function isAllowedUrl(raw) {
  try {
    const u = new URL(raw);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
    if (isBlockedHost(u.hostname)) return false;
    return true;
  } catch { return false; }
}

// ── Tracker blocklist (lightweight) ──────────────────────────────────────────
const TRACKER_PATTERNS = [
  /google-analytics\.com/, /googletagmanager\.com/, /doubleclick\.net/,
  /facebook\.net/, /fbcdn\.net/, /analytics\.twitter\.com/,
  /scorecardresearch\.com/, /quantserve\.com/, /hotjar\.com/,
  /amazon-adsystem\.com/, /googlesyndication\.com/,
];

function isTracker(url) {
  return TRACKER_PATTERNS.some(p => p.test(url));
}

// ── Session store ─────────────────────────────────────────────────────────────
const sessions = new Map();

function createSession() {
  const id = crypto.randomUUID();
  sessions.set(id, {
    id,
    cookies: new Map(),   // domain -> "name=value; name2=value2"
    lastActivity: Date.now(),
  });
  return id;
}

function getSession(id) {
  const s = sessions.get(id);
  if (!s) return null;
  if (Date.now() - s.lastActivity > SESSION_TTL_MS) {
    sessions.delete(id);
    return null;
  }
  s.lastActivity = Date.now();
  return s;
}

// Parse Set-Cookie headers into session jar
function storeCookies(session, domain, setCookieHeaders) {
  if (!setCookieHeaders || !session) return;
  const headers = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
  const existing = session.cookies.get(domain) || '';
  const jar = new Map();
  // Seed from existing
  for (const pair of existing.split(';')) {
    const [k, ...v] = pair.trim().split('=');
    if (k) jar.set(k.trim(), v.join('=').trim());
  }
  for (const h of headers) {
    const nameVal = h.split(';')[0].trim();
    const eq = nameVal.indexOf('=');
    if (eq === -1) continue;
    const name = nameVal.slice(0, eq).trim();
    const value = nameVal.slice(eq + 1).trim();
    if (value.length < 4096) jar.set(name, value);
  }
  session.cookies.set(domain, [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; '));
}

function getCookies(session, domain) {
  if (!session) return '';
  // Match exact domain + parent domains
  const parts = [];
  for (const [d, c] of session.cookies) {
    if (domain === d || domain.endsWith('.' + d)) parts.push(c);
  }
  return parts.join('; ');
}

// Sweep expired sessions every 5 min
setInterval(() => {
  const now = Date.now();
  for (const [id, s] of sessions) {
    if (now - s.lastActivity > SESSION_TTL_MS) sessions.delete(id);
  }
}, 5 * 60 * 1000).unref();

// ── Outbound fetch ────────────────────────────────────────────────────────────
const STRIP_REQ_HEADERS = new Set([
  'x-forwarded-for','x-real-ip','x-forwarded-host','x-forwarded-proto',
  'via','forwarded','cf-connecting-ip','cf-ray','x-access-token',
  'host',  // we set this ourselves
]);

const SAFE_RES_HEADERS = new Set([
  'content-type','content-length','content-encoding',
  'cache-control','expires','last-modified','etag',
  'accept-ranges','content-range',
]);

const SCRUB_RES_HEADERS = new Set([
  'server','x-powered-by','x-aspnet-version','set-cookie',
  'x-generator','via','x-cache','x-varnish','x-request-id',
  'nel','report-to','expect-ct','access-control-allow-origin',
  'access-control-allow-credentials',
]);

const UA = 'Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0';

function outboundFetch(targetUrl, session, opts = {}) {
  return new Promise((resolve, reject) => {
    if (!isAllowedUrl(targetUrl)) return reject(Object.assign(new Error('URL not allowed'), { status: 403 }));
    if (isTracker(targetUrl)) return reject(Object.assign(new Error('Blocked'), { status: 403 }));

    const parsed = new URL(targetUrl);
    const cookies = getCookies(session, parsed.hostname);

    const reqHeaders = {
      'User-Agent': UA,
      'Accept': opts.accept || 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.5',
      'Accept-Encoding': 'identity',  // avoid compressed responses we can't easily decode
      'DNT': '1',
      'Sec-GPC': '1',
      'Connection': 'close',
      'Host': parsed.host,
      ...(cookies ? { 'Cookie': cookies } : {}),
      ...(opts.headers || {}),
    };

    // Strip anything that reveals our infrastructure
    for (const k of STRIP_REQ_HEADERS) delete reqHeaders[k];

    const lib = parsed.protocol === 'https:' ? https : http;
    const reqOpts = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: opts.method || 'GET',
      headers: reqHeaders,
    };

    const req = lib.request(reqOpts, (res) => {
      // Follow redirects (up to 5)
      const redirectCount = (opts._redirects || 0);
      if ([301,302,303,307,308].includes(res.statusCode) && res.headers.location && redirectCount < 5) {
        const next = new URL(res.headers.location, targetUrl).toString();
        res.resume();
        return outboundFetch(next, session, { ...opts, _redirects: redirectCount + 1 })
          .then(resolve).catch(reject);
      }

      // Store cookies
      const setCookie = res.headers['set-cookie'];
      if (setCookie) storeCookies(session, parsed.hostname, setCookie);

      // Filter response headers
      const safeHeaders = { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' };
      for (const [k, v] of Object.entries(res.headers)) {
        const lower = k.toLowerCase();
        if (SCRUB_RES_HEADERS.has(lower)) continue;
        if (SAFE_RES_HEADERS.has(lower)) safeHeaders[k] = v;
      }

      // Buffer body (max 5MB)
      const chunks = [];
      let total = 0;
      res.on('data', chunk => {
        total += chunk.length;
        if (total > 5 * 1024 * 1024) { req.destroy(); reject(Object.assign(new Error('Response too large'), { status: 502 })); }
        else chunks.push(chunk);
      });
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: safeHeaders,
        contentType: (res.headers['content-type'] || '').split(';')[0].trim(),
        body: Buffer.concat(chunks),
        finalUrl: targetUrl,
      }));
      res.on('error', reject);
    });

    req.setTimeout(15000, () => { req.destroy(); reject(Object.assign(new Error('Request timeout'), { status: 504 })); });
    req.on('error', err => reject(Object.assign(err, { status: 502 })));

    if (opts.body) req.write(opts.body);
    req.end();
  });
}

// ── HTML rewriting — proxy all links/assets ───────────────────────────────────
function rewriteUrl(raw, base, sid) {
  try {
    const abs = new URL(raw, base).toString();
    if (!abs.startsWith('http')) return raw;
    return `/proxy?url=${encodeURIComponent(abs)}&sid=${sid}`;
  } catch { return raw; }
}

function rewriteHtml(html, base, sid) {
  let trackerCount = 0;
  // Remove known tracker scripts
  html = html.replace(/<script[^>]+src=["']([^"']+)["'][^>]*><\/script>/gi, (m, src) => {
    if (isTracker(src)) { trackerCount++; return '<!-- tracker blocked -->'; }
    return m;
  });
  // Remove inline tracking pixels
  html = html.replace(/<img[^>]+src=["']([^"']+)["'][^>]*/gi, (m, src) => {
    if (isTracker(src)) { trackerCount++; return '<!-- tracker pixel blocked'; }
    return m;
  });

  // Rewrite href, src, action, srcset attributes
  html = html.replace(/\b(href|src|action)=["']([^"']+)["']/gi, (m, attr, val) => {
    if (val.startsWith('data:') || val.startsWith('javascript:') || val.startsWith('#') || val.startsWith('mailto:')) return m;
    return `${attr}="${rewriteUrl(val, base, sid)}"`;
  });

  // Rewrite srcset
  html = html.replace(/srcset=["']([^"']+)["']/gi, (_, srcset) => {
    const rewritten = srcset.split(',').map(part => {
      const [url, ...rest] = part.trim().split(/\s+/);
      return [rewriteUrl(url, base, sid), ...rest].join(' ');
    }).join(', ');
    return `srcset="${rewritten}"`;
  });

  // Inject privacy banner + base suppression
  const banner = `
<style>
  #pr-banner{position:fixed;bottom:0;left:0;right:0;background:#111;color:#eee;
  font:13px/1.4 system-ui,sans-serif;padding:8px 16px;display:flex;
  justify-content:space-between;align-items:center;z-index:2147483647;
  border-top:2px solid #7c3aed;box-shadow:0 -2px 12px rgba(0,0,0,.4)}
  #pr-banner a{color:#a78bfa;text-decoration:none}
  #pr-banner button{background:#7c3aed;border:0;color:#fff;padding:4px 12px;
  border-radius:4px;cursor:pointer;font-size:12px}
</style>
<div id="pr-banner">
  <span>🔒 <strong>PrivateRoute Mini</strong> — IP hidden · ${trackerCount} tracker${trackerCount!==1?'s':''} blocked</span>
  <div style="display:flex;gap:8px;align-items:center">
    <a href="/">← Home</a>
    <button onclick="document.getElementById('pr-banner').remove()">Dismiss</button>
  </div>
</div>`;

  // Insert banner before </body> or at end
  if (html.includes('</body>')) {
    html = html.replace('</body>', banner + '</body>');
  } else {
    html += banner;
  }

  return html;
}

// ── Request router ────────────────────────────────────────────────────────────
function parseQuery(search) {
  const q = {};
  for (const [k, v] of new URLSearchParams(search)) q[k] = v;
  return q;
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

function sendHtml(res, status, headers, html) {
  res.writeHead(status, { ...headers, 'Content-Type': 'text/html; charset=utf-8', 'X-Frame-Options': 'DENY' });
  res.end(html);
}

// Simple HTML UI
const HOME_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PrivateRoute Mini</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,sans-serif;background:#0f0f13;color:#e2e8f0;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px}
  .card{background:#1a1a2e;border:1px solid #2d2d4e;border-radius:12px;padding:40px;width:100%;max-width:520px;box-shadow:0 8px 32px rgba(0,0,0,.4)}
  h1{font-size:1.6rem;font-weight:700;color:#a78bfa;margin-bottom:6px}
  .sub{font-size:.875rem;color:#94a3b8;margin-bottom:28px}
  .row{display:flex;gap:8px;margin-bottom:16px}
  input{flex:1;background:#0f0f1a;border:1px solid #3d3d6e;border-radius:8px;padding:10px 14px;color:#e2e8f0;font-size:.95rem;outline:none}
  input:focus{border-color:#7c3aed}
  button{background:#7c3aed;border:0;color:#fff;padding:10px 20px;border-radius:8px;cursor:pointer;font-weight:600;font-size:.9rem;white-space:nowrap}
  button:hover{background:#6d28d9}
  .badges{display:flex;gap:8px;flex-wrap:wrap;margin-top:20px}
  .badge{background:#1e1b4b;border:1px solid #3730a3;border-radius:20px;padding:4px 12px;font-size:.78rem;color:#a5b4fc}
  .footer{margin-top:24px;font-size:.75rem;color:#64748b;text-align:center}
</style>
</head>
<body>
<div class="card">
  <h1>🔒 PrivateRoute Mini</h1>
  <p class="sub">Browse privately. Your IP stays hidden from every site you visit.</p>
  <form method="GET" action="/go">
    <div class="row">
      <input name="url" type="text" placeholder="https://example.com" autofocus autocomplete="off" spellcheck="false">
      <button type="submit">Go</button>
    </div>
    <div class="row">
      <input name="q" type="text" placeholder="Search DuckDuckGo privately…">
      <button type="submit" formaction="/search">Search</button>
    </div>
  </form>
  <div class="badges">
    <span class="badge">🛡 IP hidden</span>
    <span class="badge">🚫 Trackers blocked</span>
    <span class="badge">🍪 Cookies isolated</span>
    <span class="badge">🔐 Sessions ephemeral</span>
  </div>
  <p class="footer">No browsing activity is logged. Sessions expire after 30 minutes of inactivity.</p>
</div>
</body>
</html>`;

async function router(req, res) {
  // Add security headers to every response
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');

  // Access token check
  if (ACCESS_TOKEN) {
    const token = req.headers['x-access-token'] || parseQuery(new URL(req.url, 'http://x').search).token;
    if (token !== ACCESS_TOKEN && req.url !== '/health') {
      return sendJson(res, 401, { error: 'Unauthorized' });
    }
  }

  const { pathname, search } = new URL(req.url, 'http://x');
  const q = parseQuery(search);

  // ── GET / ─────────────────────────────────────────────────────────────────
  if (pathname === '/' && req.method === 'GET') {
    return sendHtml(res, 200, {}, HOME_HTML);
  }

  // ── GET /health ───────────────────────────────────────────────────────────
  if (pathname === '/health') {
    return sendJson(res, 200, { status: 'ok', sessions: sessions.size, ts: Date.now() });
  }

  // ── GET /go?url= — navigate with auto-session ─────────────────────────────
  if (pathname === '/go' && req.method === 'GET') {
    let target = q.url || '';
    if (!target) return sendHtml(res, 400, {}, '<p>No URL provided.</p>');
    if (!/^https?:\/\//i.test(target)) target = 'https://' + target;

    let sid = q.sid;
    if (!sid || !getSession(sid)) sid = createSession();
    const session = getSession(sid);

    try {
      const result = await outboundFetch(target, session);
      let html = result.body.toString('utf8');
      html = rewriteHtml(html, result.finalUrl, sid);
      return sendHtml(res, result.status, result.headers, html);
    } catch (err) {
      return sendJson(res, err.status || 502, { error: err.message });
    }
  }

  // ── GET /search?q= — DuckDuckGo privacy search ───────────────────────────
  if (pathname === '/search' && req.method === 'GET') {
    const query = q.q || '';
    if (!query) return res.writeHead(302, { Location: '/' }), res.end();

    let sid = q.sid;
    if (!sid || !getSession(sid)) sid = createSession();
    const session = getSession(sid);

    const ddgUrl = `https://html.duckduckgo.com/html/?${new URLSearchParams({ q: query, kl: 'us-en', kp: '-2' })}`;
    try {
      const result = await outboundFetch(ddgUrl, session, { accept: 'text/html' });
      let html = result.body.toString('utf8');
      html = rewriteHtml(html, ddgUrl, sid);
      return sendHtml(res, 200, result.headers, html);
    } catch (err) {
      return sendJson(res, err.status || 502, { error: err.message });
    }
  }

  // ── GET /proxy?url=&sid= — asset/page proxy ───────────────────────────────
  if (pathname === '/proxy' && req.method === 'GET') {
    const rawUrl = q.url ? decodeURIComponent(q.url) : '';
    const sid = q.sid || '';
    if (!rawUrl) return sendJson(res, 400, { error: 'Missing url' });

    const session = getSession(sid);

    try {
      const result = await outboundFetch(rawUrl, session);
      const ct = result.contentType;

      if (ct.includes('text/html')) {
        let html = result.body.toString('utf8');
        html = rewriteHtml(html, result.finalUrl, sid);
        return sendHtml(res, result.status, result.headers, html);
      }

      if (ct.includes('text/css')) {
        // Rewrite url() in CSS
        let css = result.body.toString('utf8');
        css = css.replace(/url\(["']?([^"')]+)["']?\)/gi, (m, u) => {
          if (u.startsWith('data:')) return m;
          try {
            const abs = new URL(u, rawUrl).toString();
            return `url("/proxy?url=${encodeURIComponent(abs)}&sid=${sid}")`;
          } catch { return m; }
        });
        res.writeHead(result.status, { ...result.headers, 'Content-Type': 'text/css; charset=utf-8' });
        return res.end(css);
      }

      res.writeHead(result.status, result.headers);
      return res.end(result.body);
    } catch (err) {
      return sendJson(res, err.status || 502, { error: err.message });
    }
  }

  // ── POST /proxy-form?url=&sid= — form submission ──────────────────────────
  if (pathname === '/proxy-form' && req.method === 'POST') {
    const rawUrl = q.url ? decodeURIComponent(q.url) : '';
    const sid = q.sid || '';
    if (!rawUrl) return sendJson(res, 400, { error: 'Missing url' });

    const session = getSession(sid);
    const ct = req.headers['content-type'] || 'application/x-www-form-urlencoded';

    const bodyChunks = [];
    for await (const chunk of req) bodyChunks.push(chunk);
    const body = Buffer.concat(bodyChunks);

    try {
      const result = await outboundFetch(rawUrl, session, {
        method: 'POST',
        headers: { 'Content-Type': ct },
        body,
      });
      if (result.contentType.includes('text/html')) {
        let html = result.body.toString('utf8');
        html = rewriteHtml(html, result.finalUrl, sid);
        return sendHtml(res, result.status, result.headers, html);
      }
      res.writeHead(result.status, result.headers);
      return res.end(result.body);
    } catch (err) {
      return sendJson(res, err.status || 502, { error: err.message });
    }
  }

  // ── 404 ───────────────────────────────────────────────────────────────────
  sendJson(res, 404, { error: 'Not found' });
}

// ── Server ────────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  try {
    await router(req, res);
  } catch (err) {
    console.error('Unhandled error:', err);
    if (!res.headersSent) sendJson(res, 500, { error: 'Internal server error' });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`PrivateRoute Mini running on port ${PORT}`);
});

process.on('SIGTERM', () => { server.close(() => process.exit(0)); });
process.on('SIGINT',  () => { server.close(() => process.exit(0)); });
