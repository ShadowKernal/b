(function () {
  const COOKIE = {
    session: 'ums_session',
    csrf: 'ums_csrf'
  };

  function getCookie(name) {
    const parts = document.cookie.split(';').map(p => p.trim());
    for (const part of parts) {
      if (!part) continue;
      const eq = part.indexOf('=');
      if (eq === -1) continue;
      const k = decodeURIComponent(part.slice(0, eq));
      const v = decodeURIComponent(part.slice(eq + 1));
      if (k === name) return v;
    }
    return null;
  }

  async function api(path, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    const headers = new Headers(options.headers || {});
    let body = options.body;

    const hasBody = body !== undefined && body !== null;
    if (hasBody && !(body instanceof FormData) && typeof body !== 'string') {
      headers.set('Content-Type', 'application/json');
      body = JSON.stringify(body);
    }

    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      const csrf = getCookie(COOKIE.csrf);
      if (csrf) headers.set('X-CSRF-Token', csrf);
    }

    const resp = await fetch(path, {
      method,
      headers,
      body: hasBody ? body : undefined,
      credentials: 'include'
    });

    const contentType = (resp.headers.get('content-type') || '').toLowerCase();
    let data = null;
    if (contentType.includes('application/json')) {
      data = await resp.json().catch(() => null);
    } else {
      data = await resp.text().catch(() => null);
    }

    return { ok: resp.ok, status: resp.status, data, resp };
  }

  function setStatus(el, message, kind) {
    if (!el) return;
    el.classList.remove('ok', 'err');
    if (kind === 'ok') el.classList.add('ok');
    if (kind === 'err') el.classList.add('err');
    el.textContent = message || '';
  }

  function qs(name) {
    const url = new URL(window.location.href);
    return url.searchParams.get(name);
  }

  function fmtTs(ts) {
    if (!ts) return '';
    try {
      const d = new Date(ts);
      if (Number.isNaN(d.getTime())) return String(ts);
      return d.toLocaleString();
    } catch {
      return String(ts);
    }
  }

  window.UMS = {
    COOKIE,
    api,
    getCookie,
    setStatus,
    qs,
    fmtTs
  };
})();

