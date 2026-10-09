"""Minimal HTML pages: login, consent, errors, demo callback.

No template engine — the forms are small and EVERY interpolated value goes
through html.escape(). (If this grew past ~4 pages, switch to Jinja2 with
autoescaping on; hand-rolled templating is where XSS slips in.)

Security properties encoded in the markup itself:
- login form posts to /login with `next` as a hidden field → `next` is
  validated server-side to start with "/" (open-redirect guard)
- consent form echoes the *validated* authorize params — but the server
  RE-VALIDATES all of them on POST (hidden fields are attacker-controlled)
- no inline scripts, no third-party assets (CSP-trivial)
"""
from __future__ import annotations

from html import escape


def error_page(*, title: str, detail: str) -> str:
    """The page shown when a redirect would be UNSAFE (bad client_id /
    redirect_uri). Rendering instead of redirecting is the open-redirect
    kill-switch: we never send the browser anywhere we haven't verified."""
    return f"""<!doctype html>
<html><head><title>{escape(title)}</title></head>
<body style="font-family: sans-serif; max-width: 40rem; margin: 4rem auto;">
  <h1>{escape(title)}</h1>
  <p>{escape(detail)}</p>
  <p style="color:#666">This error was <strong>not</strong> forwarded to any
  redirect URI, because the redirect target could not be trusted.</p>
</body></html>"""


def login_form(*, next_url: str, error: str | None = None) -> str:
    error_html = f'<p style="color:#b00020">{escape(error)}</p>' if error else ""
    return f"""<!doctype html>
<html><head><title>Sign in — agent-auth-lab</title></head>
<body style="font-family: sans-serif; max-width: 24rem; margin: 4rem auto;">
  <h1>Sign in</h1>
  {error_html}
  <form method="post" action="/login">
    <input type="hidden" name="next" value="{escape(next_url)}">
    <p><label>Email<br><input name="email" type="email" required
         style="width:100%"></label></p>
    <p><label>Password<br><input name="password" type="password" required
         style="width:100%"></label></p>
    <button type="submit">Sign in</button>
  </form>
  <p style="color:#666; font-size:.85rem">Demo users: alice@example.com /
  correct-horse-battery &nbsp;·&nbsp; bob@example.com / bob-not-a-real-secret</p>
</body></html>"""


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
) -> str:
    scope_items = "".join(
        f"<li><code>{escape(s)}</code></li>" for s in scope.split()
    )
    nonce_field = (
        f'<input type="hidden" name="nonce" value="{escape(nonce)}">'
        if nonce else ""
    )
    resource_field = (
        f'<input type="hidden" name="resource" value="{escape(resource)}">'
        if resource else ""
    )
    return f"""<!doctype html>
<html><head><title>Authorize — agent-auth-lab</title></head>
<body style="font-family: sans-serif; max-width: 28rem; margin: 4rem auto;">
  <h1>Authorize application</h1>
  <p>Signed in as <strong>{escape(user_label)}</strong></p>
  <p><strong>{escape(client_id)}</strong> is requesting:</p>
  <ul>{scope_items}</ul>
  <p style="color:#666; font-size:.85rem">Redirect to:
     <code>{escape(redirect_uri)}</code></p>
  <form method="post" action="/consent" style="display:inline">
    <input type="hidden" name="client_id" value="{escape(client_id)}">
    <input type="hidden" name="redirect_uri" value="{escape(redirect_uri)}">
    <input type="hidden" name="scope" value="{escape(scope)}">
    <input type="hidden" name="state" value="{escape(state)}">
    <input type="hidden" name="code_challenge" value="{escape(code_challenge)}">
    <input type="hidden" name="code_challenge_method"
           value="{escape(code_challenge_method)}">
    {nonce_field}
    {resource_field}
    <button name="decision" value="approve">Approve</button>
    <button name="decision" value="deny">Deny</button>
  </form>
</body></html>"""


def callback_page(*, code: str | None, state: str | None,
                  error: str | None, error_description: str | None) -> str:
    """Landing page for the lab's registered redirect URI — shows what the
    client received, so the flow is inspectable in a browser."""
    if error:
        body = f"<h2>Error: {escape(error)}</h2><p>{escape(error_description or '')}</p>"
    else:
        body = (
            f"<h2>Authorization code received</h2>"
            f"<p><code>code = {escape(code or '')}</code></p>"
            f"<p><code>state = {escape(state or '')}</code></p>"
            f"<p style='color:#666'>Exchange it at POST /token with the "
            f"PKCE verifier — the code alone is useless without it.</p>"
        )
    return f"""<!doctype html>
<html><head><title>Demo callback</title></head>
<body style="font-family: sans-serif; max-width: 40rem; margin: 4rem auto;">
{body}
</body></html>"""
