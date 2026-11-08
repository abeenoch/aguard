"""Principal factory (Phase 1 step 2). One DCR client per agent per episode, one human
login reused via session cookie. Real auth-code + PKCE flow, client_secret_basic at /token.
Writes agents(episode_id, idx, role, client_id) to results.sqlite."""
import base64, hashlib, json, os, secrets, sqlite3, time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client

AS = "http://127.0.0.1:8180"
MCP_URL = "http://127.0.0.1:8181/mcp"
REDIRECT = f"{AS}/demo/callback"
SCOPE = "openid email orders:read"
EMAIL = os.environ.get("EXP_USER_EMAIL", "alice@example.com")           # README demo account
PASSWORD = os.environ.get("EXP_USER_PASSWORD", "correct-horse-battery")
DB = Path("/root/aguard/experiments/results/results.sqlite")


@dataclass
class Principal:
    episode_id: str
    idx: int
    role: str          # "team" | "bystander"
    name: str
    client_id: str
    access_token: str


def _must(r, ok, what):
    if r.status_code not in ok:
        raise RuntimeError(f"{what}: HTTP {r.status_code} {r.text[:300]}")
    return r


class PrincipalFactory:
    def __init__(self):
        self.http = httpx.Client(timeout=30, follow_redirects=False)
        self._login()
        self.db = sqlite3.connect(DB)
        self.db.execute("CREATE TABLE IF NOT EXISTS agents(episode_id TEXT, idx INT, role TEXT, "
                        "name TEXT, client_id TEXT, created REAL, PRIMARY KEY(episode_id, idx))")

    def _login(self):
        for _ in range(3):
            r = self.http.post(f"{AS}/login", data={"email": EMAIL, "password": PASSWORD, "next": "/"})
            if r.status_code != 429:
                break
            time.sleep(float(r.headers.get("retry-after", "15")) + 1)
        _must(r, (200, 303), "login")

    def _register(self, name):
        r = self.http.post(f"{AS}/register", json={
            "client_name": name, "redirect_uris": [REDIRECT],
            "grant_types": ["authorization_code"], "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_basic", "scope": SCOPE})
        d = _must(r, (200, 201), "register").json()
        return d["client_id"], d["client_secret"]

    def _token(self, cid, secret):
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        q = {"client_id": cid, "redirect_uri": REDIRECT, "scope": SCOPE, "state": "st-exp",
             "code_challenge": challenge, "code_challenge_method": "S256", "resource": MCP_URL}
        r = self.http.get(f"{AS}/authorize", params={"response_type": "code", **q})
        if r.status_code == 302 and "/login" in r.headers.get("location", ""):
            self._login()
        r = _must(self.http.post(f"{AS}/consent", data={"decision": "approve", **q}), (302,), "consent")
        code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
        basic = base64.b64encode(f"{cid}:{secret}".encode()).decode()
        r = self.http.post(f"{AS}/token", headers={"Authorization": f"Basic {basic}"},
                           data={"grant_type": "authorization_code", "code": code,
                                 "redirect_uri": REDIRECT, "code_verifier": verifier})
        return _must(r, (200,), "token").json()["access_token"]

    def make(self, episode_id: str, idx: int, role: str) -> Principal:
        name = f"exp-{episode_id}-{idx}"
        cid, secret = self._register(name)
        tok = self._token(cid, secret)
        self.db.execute("INSERT OR REPLACE INTO agents VALUES(?,?,?,?,?,?)",
                        (episode_id, idx, role, name, cid, time.time()))
        self.db.commit()
        return Principal(episode_id, idx, role, name, cid, tok)


def claims(jwt: str) -> dict:
    seg = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


@asynccontextmanager
async def mcp_session(token: str):
    async with streamablehttp_client(MCP_URL, headers={"Authorization": f"Bearer {token}"}) as (r, w, _):
        async with ClientSession(r, w) as s:
            await s.initialize()
            yield s


def payload(result):
    sc = getattr(result, "structuredContent", None)
    if isinstance(sc, dict) and set(sc) == {"result"}:
        return sc["result"]
    for b in result.content or []:
        if getattr(b, "type", None) == "text":
            return json.loads(b.text)