"""vrymdor-mcp: connect Claude Desktop, Cursor, VS Code or any MCP client to your Vrymdor AI Node, no Docker needed.

Desktop MCP clients start a local command and talk to it over standard input and output. This command relays each
message to your node's MCP endpoint (POST /mcp) and writes the node's answer back. It trades the Agent ID and Agent
Secret for a short-lived token and renews it a minute before it expires, so the client never handles a token.

    uvx --from vrymdor-node vrymdor-mcp            # what the MCP client runs
    uvx --from vrymdor-node vrymdor-mcp --check    # one-time test: does the node accept this agent?

Settings come from the environment (the MCP client's "env" block):

    VRYMNOX_NODE_URL      your Node Host URL, for example https://node.vrymdor.com/t/abc123def456
                          or http://localhost:8080 for a node on this computer
    VRYMNOX_AGENT_ID      agt_...
    VRYMNOX_AGENT_SECRET  vrym_agent_...

The VRYMDOR_ spellings (VRYMDOR_NODE_URL and so on, as in the GitHub Action) work too. Standard output carries only
MCP messages; anything for a person goes to standard error.
"""
from __future__ import annotations

import io
import json
import os
import sys
import time
from typing import TextIO

import httpx

NAMES = {"url": ("VRYMNOX_NODE_URL", "VRYMDOR_NODE_URL"),
         "id": ("VRYMNOX_AGENT_ID", "VRYMDOR_AGENT_ID"),
         "secret": ("VRYMNOX_AGENT_SECRET", "VRYMDOR_AGENT_SECRET")}


def version() -> str:
    try:
        from importlib.metadata import version as _v

        return _v("vrymdor-node")
    except Exception:  # noqa: BLE001 (running from a source checkout)
        return "0"


def user_agent() -> str:
    # Our own name: a stock library name (Python-urllib, python-httpx) can be refused by Cloudflare's browser check in
    # front of a hosted node.
    return f"vrymdor-mcp/{version()}"


def clean_url(raw: str) -> str:
    """Forgive the usual paste mistakes: spaces, quotes, a slash at the end, or the Token URL ending in /v1/token."""
    url = raw.strip().strip("\"'").strip().rstrip("/")
    if url.endswith("/v1/token"):
        url = url[: -len("/v1/token")].rstrip("/")
    return url


def setting(key: str, env: dict | None = None) -> str:
    env = os.environ if env is None else env
    for name in NAMES[key]:
        if env.get(name, "").strip():
            return env[name].strip().strip("\"'").strip()
    return ""


def refusal(status: int, raw: bytes) -> str:
    """Why the token was refused, in words: the node's own reason, or that something in front of it answered."""
    text = (raw or b"")[:2000].decode("utf-8", "replace")
    try:
        doc = json.loads(text)
        detail = doc.get("detail") or doc.get("error") if isinstance(doc, dict) else None
    except ValueError:
        detail = None
    if isinstance(detail, dict):
        detail = detail.get("message") or detail.get("code")
    if detail:
        return f"the node refused the agent (HTTP {status}): {str(detail)[:200]}"
    low = text.lower()
    if "cloudflare" in low or "error code: 10" in low:
        return (f"the request was blocked before it reached the node (HTTP {status}, Cloudflare). Check the Node Host "
                "URL is the one from your Vrymdor dashboard")
    if status == 401:
        return "the node refused the agent (HTTP 401): the Agent ID or Agent Secret is wrong"
    if status == 404:
        return "the node answered 404: the Node Host URL is wrong. Copy it again from your Vrymdor dashboard"
    if status in (502, 503, 504):
        return f"the node is not answering (HTTP {status}). If it is a hosted node, turn it on in Home base"
    return f"the node refused the agent (HTTP {status})"


class Bridge:
    def __init__(self, url: str, agent_id: str, secret: str, *, http: httpx.Client | None = None) -> None:
        self.url, self.agent_id, self._secret = clean_url(url), agent_id, secret
        self._http = http or httpx.Client(timeout=120.0, headers={"User-Agent": user_agent()})
        self._token, self._expires = "", 0.0
        self._session = ""

    def token(self) -> str:
        if self._token and time.time() < self._expires - 60:
            return self._token
        r = self._http.post(f"{self.url}/v1/token", json={"agent_id": self.agent_id, "agent_secret": self._secret})
        if r.status_code != 200:
            raise RuntimeError(refusal(r.status_code, r.content))
        doc = r.json()
        self._token, self._expires = doc["access_token"], time.time() + int(doc.get("expires_in", 600))
        return self._token

    def _send(self, line: str) -> httpx.Response:
        def post() -> httpx.Response:
            headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                       "Authorization": f"Bearer {self.token()}"}
            if self._session:
                headers["Mcp-Session-Id"] = self._session
            return self._http.post(f"{self.url}/mcp", content=line.encode("utf-8"), headers=headers)

        r = post()
        if r.status_code == 401:   # the token was revoked or the node restarted: get a fresh one and try once more
            self._token, self._expires = "", 0.0
            r = post()
        if r.headers.get("mcp-session-id"):
            self._session = r.headers["mcp-session-id"]
        return r

    def handle(self, line: str, err: TextIO = sys.stderr) -> str | None:
        try:
            msg = json.loads(line)
        except ValueError:
            return json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
        has_id = isinstance(msg, dict) and "id" in msg
        try:
            r = self._send(line)
        except (httpx.HTTPError, RuntimeError, ValueError, KeyError) as exc:
            reason = why(exc, self.url)
            print(f"vrymdor-mcp: {reason}", file=err, flush=True)
            if has_id:
                return json.dumps({"jsonrpc": "2.0", "id": msg.get("id"),
                                   "error": {"code": -32603, "message": f"Your Vrymdor AI Node could not be reached: {reason}"}})
            return None
        if r.status_code == 202 or not r.content:
            return None   # a notification
        text = r.content.decode("utf-8")
        if r.headers.get("content-type", "").split(";")[0].strip().lower() == "text/event-stream":
            return sse_messages(text) or None
        return text


def sse_messages(text: str) -> str:
    """A streamed answer (text/event-stream): each event's data lines joined, one JSON message per output line."""
    out, data = [], []
    for raw in text.replace("\r\n", "\n").split("\n"):
        if raw.startswith("data:"):
            data.append(raw[5:].lstrip(" "))
        elif raw == "" and data:
            out.append("".join(data))
            data = []
    if data:
        out.append("".join(data))
    return "\n".join(m for m in out if m.strip())


def why(exc: Exception, url: str) -> str:
    """An exception in words: no connection is the usual case, and it is the address or a node that is off."""
    if isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout)):
        return f"could not reach {url} (check the Node Host URL, and that your node is on)"
    if isinstance(exc, httpx.TimeoutException):
        return f"{url} did not answer in time"
    return str(exc)


def _utf8(stream: TextIO) -> None:
    # MCP messages are UTF-8 with \n line endings; a Windows console default (cp1252, \r\n) would damage them.
    try:
        stream.reconfigure(encoding="utf-8", newline="\n")   # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass


def check(bridge: Bridge, out: TextIO = sys.stdout) -> int:
    """--check: get a token and list the tools, then say in words whether it works."""
    try:
        bridge.token()
        doc = json.loads(bridge.handle(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
                                       err=io.StringIO()) or "{}")
        if doc.get("error"):
            raise RuntimeError(str(doc["error"].get("message") or doc["error"]).rstrip("."))
        tools = [t.get("name") for t in doc.get("result", {}).get("tools", [])]
    except (httpx.HTTPError, RuntimeError, ValueError, KeyError) as exc:
        print(f"Not connected: {why(exc, bridge.url)}.", file=out)
        return 1
    if not tools:
        print("Connected, but the node listed no tools for this agent. Check the agent's role in your policy.", file=out)
        return 1
    first = sorted(tools, key=lambda n: (n != "vrymnox_sanitize", not str(n).startswith("vrymnox_"), str(n)))[:4]
    print(f"Connected: your node accepted this agent and offers {len(tools)} tools, including "
          f"{', '.join(map(str, first))}.", file=out)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if "--version" in args:
        print(f"vrymdor-mcp {version()}")
        return 0
    if "-h" in args or "--help" in args:
        print(__doc__)
        return 0
    missing = [NAMES[k][0] for k in ("url", "id", "secret") if not setting(k)]
    if missing:
        print(f"vrymdor-mcp: set {', '.join(missing)} (in your MCP client's env block)", file=sys.stderr)
        return 2
    url = setting("url")
    if not url.startswith(("http://", "https://")):
        print("vrymdor-mcp: VRYMNOX_NODE_URL must start with https:// (or http:// for a node on this computer)",
              file=sys.stderr)
        return 2
    bridge = Bridge(url, setting("id"), setting("secret"))
    if "--check" in args:
        return check(bridge)
    _utf8(sys.stdin)
    _utf8(sys.stdout)
    try:
        for line in sys.stdin:
            if line.strip():
                out = bridge.handle(line.strip())
                if out is not None:
                    sys.stdout.write(out + "\n")
                    sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
