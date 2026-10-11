"""HTML pages: sign in, sign up, consent, errors, demo callback.

No template engine — the pages are small and EVERY interpolated value goes
through html.escape(). (This is the point where hand-rolled templating starts to
cost more than it saves: the Jinja2 migration with autoescaping on is E1 in
docs/DESIGN.md.) One shared stylesheet keeps them visually identical.

Security properties encoded in the markup itself:
- every form action is prefixed with the AS's public path prefix (see
  aguard/oidc/urls.py): behind a path-stripping proxy the app sees "/login",
  but the BROWSER must post to "/api/login" or it hits the origin root
- `next` is a hidden field validated server-side to start with "/"
  (open-redirect guard) — a form is just another way to be handed attacker data
- consent form echoes the *validated* authorize params, but the server
  RE-VALIDATES all of them on POST (hidden fields are attacker-controlled)
- no inline scripts, no third-party assets, no external fonts (CSP-trivial)
"""
from __future__ import annotations

from html import escape
from urllib.parse import quote

# One stylesheet for every page: dark, near-black, a single gold accent — the
# palette of the public site, applied with the restraint of a modern dev-tool
# form (system sans for prose, mono for anything machine-ish, hairline borders,
# generous padding, no decoration that is not doing work). Inlined so a page
# renders with zero extra requests and a trivial CSP.
_STYLE = """
:root{
  --bg:#06070c;--panel:#10131c;--field:#0b0d14;--ink:#e8eaf0;
  --muted:#9aa6b8;--line:rgba(255,255,255,.10);--gold:#f5c542;--gold-ink:#191203;
  --red:#ff5c5c;--sans:"Inter","SF Pro Display",system-ui,-apple-system,"Segoe UI",sans-serif;
  --mono:ui-monospace,"SF Mono","Cascadia Code","Roboto Mono",monospace;
}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:40px 20px;
  background-color:var(--bg);color:var(--ink);font-family:var(--sans);
  font-size:15px;line-height:1.5;-webkit-font-smoothing:antialiased}
.card{width:100%;max-width:400px;background:var(--panel);border:1px solid var(--line);
  border-radius:16px;padding:32px;box-shadow:0 24px 70px -28px rgba(0,0,0,.85)}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:26px}
.dot{width:10px;height:10px;border-radius:3px;background:var(--gold);
  box-shadow:0 0 18px rgba(245,197,66,.75)}
.brand b{font-size:15px;letter-spacing:.2px}
h1{font-size:20px;margin:0 0 6px;font-weight:600;letter-spacing:-.01em}
h2{font-size:17px;margin:0 0 10px;font-weight:600}
.sub{color:var(--muted);font-size:13.5px;margin:0 0 22px}
.who{color:var(--muted);font-size:13.5px;margin:0 0 18px}
.who b{color:var(--ink);font-weight:600}
label{display:block;font-size:12.5px;color:var(--muted);margin:0 0 6px}
input{width:100%;padding:11px 13px;border-radius:10px;border:1px solid var(--line);
  background:var(--field);color:var(--ink);font:inherit;font-size:14.5px;outline:none}
input:focus{border-color:var(--gold);box-shadow:0 0 0 3px rgba(245,197,66,.16)}
.field{margin:0 0 16px}
button{width:100%;padding:12px;border-radius:10px;border:0;cursor:pointer;
  font:inherit;font-weight:600;font-size:14.5px}
.btn-primary{background:var(--gold);color:var(--gold-ink)}
.btn-primary:hover{filter:brightness(1.07)}
.btn-ghost{background:transparent;color:var(--muted);border:1px solid var(--line)}
.btn-ghost:hover{color:var(--ink);border-color:rgba(255,255,255,.28)}
.row{display:flex;gap:10px;margin-top:6px}
.note{color:var(--muted);font-size:12.5px;margin:18px 0 0;text-align:center}
.note a{color:var(--gold);text-decoration:none;font-weight:600}
.err{background:rgba(255,92,92,.10);border:1px solid rgba(255,92,92,.35);
  color:#ffd9d9;border-radius:10px;padding:10px 12px;font-size:13.5px;margin:0 0 18px}
.meta{margin-top:22px;padding-top:16px;border-top:1px solid var(--line);
  font-family:var(--mono);font-size:11.5px;color:var(--muted)}
.scopes{list-style:none;padding:0;margin:0 0 20px}
.scopes li{display:flex;align-items:center;gap:10px;padding:9px 0;
  border-bottom:1px solid var(--line);font-family:var(--mono);font-size:12.5px}
.scopes li:last-child{border-bottom:0}
.tick{color:var(--gold)}
.cli{font-family:var(--mono);font-size:12px;color:var(--muted);word-break:break-all}
"""


def _page(title: str, inner: str) -> str:
    """Wrap content in the shared shell (brand mark + card)."""
    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{escape(title)}</title>
<style>{_STYLE}</style>
</head><body>
<main class="card">
  <div class="brand"><span class="dot"></span><b>a-guard</b></div>
  {inner}
</main>
</body></html>"""


def _error_box(message: str | None) -> str:
    return f'<p class="err">{escape(message)}</p>' if message else ""


def error_page(*, title: str, detail: str) -> str:
    """Shown when a redirect would be UNSAFE (bad client_id / redirect_uri).

    Rendering instead of redirecting is the open-redirect kill-switch: we never
    send the browser anywhere we have not verified."""
    return _page(title, f"""
  <h1>{escape(title)}</h1>
  <p class="sub">{escape(detail)}</p>
  <p class="meta">This error was not forwarded to any redirect URI, because the
  redirect target could not be trusted.</p>""")


def rate_limited_page(*, retry_after: int) -> str:
    """Too many attempts from this client.

    Rendered rather than redirected for the same reason as error_page(): the
    browser is never sent anywhere we have not verified.
    """
    return _page("Too many attempts", f"""
  <h1>Too many attempts</h1>
  <p class="sub">This address has made too many attempts. Try again in
     <b>{escape(str(retry_after))}</b> seconds.</p>
  <p class="meta">The limit protects accounts from password guessing, so a
  client that keeps retrying will keep being refused.</p>""")


def login_form(*, next_url: str, error: str | None = None, prefix: str = "",
               allow_signup: bool = True, demo_users: bool = False) -> str:
    signup_note = (
        f'<p class="note">No account? <a href="{escape(prefix)}/signup'
        f'?next={quote(next_url, safe="")}">Create one</a></p>'
        if allow_signup else ""
    )
    demo_note = (
        '<p class="meta">Demo users — alice@example.com / correct-horse-battery'
        ' &nbsp;·&nbsp; bob@example.com / bob-not-a-real-secret<br>'
        'Set SEED_DEMO_USERS=false to remove them.</p>' if demo_users else ""
    )
    return _page("Sign in", f"""
  <h1>Sign in</h1>
  <p class="sub">Continue to authorize this application.</p>
  {_error_box(error)}
  <form method="post" action="{escape(prefix)}/login">
    <input type="hidden" name="next" value="{escape(next_url)}">
    <div class="field"><label for="email">Email</label>
      <input id="email" name="email" type="email" autocomplete="username"
             autofocus required></div>
    <div class="field"><label for="password">Password</label>
      <input id="password" name="password" type="password"
             autocomplete="current-password" required></div>
    <button class="btn-primary" type="submit">Sign in</button>
  </form>
  {signup_note}{demo_note}""")


def signup_form(*, next_url: str, error: str | None = None, prefix: str = "",
                email: str = "", name: str = "") -> str:
    """Self-service account creation.

    Field values are echoed back on error so a mistyped password does not cost
    the user their name and email too — and each is escaped like everything else,
    because "echo what the user sent" is exactly where XSS lives.
    """
    return _page("Create account", f"""
  <h1>Create your account</h1>
  <p class="sub">One account, one tenant — your rows are visible to you alone.</p>
  {_error_box(error)}
  <form method="post" action="{escape(prefix)}/signup">
    <input type="hidden" name="next" value="{escape(next_url)}">
    <div class="field"><label for="name">Name</label>
      <input id="name" name="name" type="text" autocomplete="name"
             value="{escape(name)}" required></div>
    <div class="field"><label for="email">Email</label>
      <input id="email" name="email" type="email" autocomplete="username"
             value="{escape(email)}" required></div>
    <div class="field"><label for="password">Password</label>
      <input id="password" name="password" type="password"
             autocomplete="new-password" minlength="10" required></div>
    <button class="btn-primary" type="submit">Create account</button>
  </form>
  <p class="note">Already have an account?
     <a href="{escape(prefix)}/login?next={quote(next_url, safe='')}">Sign in</a></p>""")


def consent_form(
    *,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str,
    nonce: str | None,
    user_label: str,
    resource: str | None = None,
    prefix: str = "",
) -> str:
    scopes = scope.split()
    scope_items = (
        "".join(f'<li><span class="tick">&#10003;</span>{escape(s)}</li>'
                for s in scopes)
        or '<li><span class="tick">&#10003;</span>basic access</li>'
    )
    nonce_field = (
        f'<input type="hidden" name="nonce" value="{escape(nonce)}">'
        if nonce else ""
    )
    resource_field = (
        f'<input type="hidden" name="resource" value="{escape(resource)}">'
        if resource else ""
    )
    return _page("Authorize application", f"""
  <h1>Authorize application</h1>
  <p class="who">Signed in as <b>{escape(user_label)}</b></p>
  <p class="sub">This application is requesting:</p>
  <ul class="scopes">{scope_items}</ul>
  <form method="post" action="{escape(prefix)}/consent">
    <input type="hidden" name="client_id" value="{escape(client_id)}">
    <input type="hidden" name="redirect_uri" value="{escape(redirect_uri)}">
    <input type="hidden" name="scope" value="{escape(scope)}">
    <input type="hidden" name="state" value="{escape(state)}">
    <input type="hidden" name="code_challenge" value="{escape(code_challenge)}">
    <input type="hidden" name="code_challenge_method"
           value="{escape(code_challenge_method)}">
    {nonce_field}
    {resource_field}
    <div class="row">
      <button class="btn-primary" name="decision" value="approve">Approve</button>
      <button class="btn-ghost" name="decision" value="deny">Deny</button>
    </div>
  </form>
  <p class="meta">{escape(client_id)}<br>{escape(redirect_uri)}</p>""")


def callback_page(*, code: str | None, state: str | None,
                  error: str | None, error_description: str | None) -> str:
    """Landing page for the lab's registered redirect URI — shows what the
    client received, so the flow is inspectable in a browser."""
    if error:
        inner = f"""
  <h1>Authorization failed</h1>
  <p class="err">{escape(error)} — {escape(error_description or '')}</p>"""
    else:
        inner = f"""
  <h1>Authorization code received</h1>
  <p class="sub">Exchange it at <span class="cli">POST /token</span> with the
     PKCE verifier — the code alone is useless without it.</p>
  <p class="cli">code&nbsp;= {escape(code or '')}<br>state = {escape(state or '')}</p>"""
    return _page("a-guard", inner)
