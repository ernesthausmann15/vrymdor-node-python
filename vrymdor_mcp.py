"""vrymdor-mcp: connect Claude Desktop, Cursor, VS Code or any MCP client to your Vrymdor AI Node, no Docker needed.

Desktop MCP clients start a local command and talk to it over standard input and output. This command relays each
message to your node's MCP endpoint (POST /mcp) and writes the node's answer back. It trades the Agent ID and Agent
Secret for a short-lived token and renews it a minute before it expires, so the client never handles a token.

    vrymdor-mcp --install-claude   # set up Claude Desktop in one step: tests the agent, writes Claude's settings
    vrymdor-mcp --check            # one-time test: does the node accept this agent?
    vrymdor-mcp                    # what the MCP client runs

Settings come from the environment (the MCP client's "env" block); --install-claude asks for any that are missing:

    VRYMNOX_NODE_URL      your Node Host URL, for example https://node.vrymdor.com/t/abc123def456
                          or http://localhost:8080 for a node on this computer
    VRYMNOX_AGENT_ID      agt_...
    VRYMNOX_AGENT_SECRET  vrym_agent_...

The VRYMDOR_ spellings (VRYMDOR_NODE_URL and so on, as in the GitHub Action) work too. Standard output carries only
MCP messages; anything for a person goes to standard error.

It trusts the certificates this computer trusts, so antivirus HTTPS scanning (Norton, Avast, AVG) and company
proxies work without any change. In the client it always shows as "vrymdor", even when the node cannot be reached,
with a vrymdor_status tool that says whether it is connected and, if not, what to fix.
"""
from __future__ import annotations

import io
import json
import os
import shutil
import ssl
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import TextIO

import httpx

try:
    from vrymnox_node import system_ssl_context
except ImportError:  # pragma: no cover (running this file on its own)
    def system_ssl_context():  # type: ignore[misc]
        return True

NAMES = {"url": ("VRYMNOX_NODE_URL", "VRYMDOR_NODE_URL"),
         "id": ("VRYMNOX_AGENT_ID", "VRYMDOR_AGENT_ID"),
         "secret": ("VRYMNOX_AGENT_SECRET", "VRYMDOR_AGENT_SECRET")}

# Claude Desktop gives up on a request after 60 seconds, so every answer must come back well inside that, even when a
# connection stalls (antivirus HTTPS scanning and some networks leave a reused connection hanging): a short wait, then
# one more try on a fresh connection.
QUICK_SECONDS = 20.0   # initialize, tools/list, ping and the token
CALL_SECONDS = 25.0    # tools/call (twice at most: 50 seconds)
RETRY_ERRORS = (httpx.TimeoutException, httpx.RemoteProtocolError, httpx.ReadError, httpx.WriteError)

STATUS_TOOL = "vrymdor_status"
SERVER_KEY = "vrymdor"
PROTOCOL = "2025-06-18"


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
        hint = ""
        if "may not receive tokens" in str(detail):
            hint = (". This agent is stopped, paused or expired: on AI agents, resume or extend it, or add a new agent "
                    "and use its Agent ID and Agent Secret")
        return f"the node refused the agent (HTTP {status}): {str(detail)[:200].rstrip('.')}{hint}"
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


def certificate_problem(exc: BaseException) -> bool:
    """True when the connection failed because the node's certificate was not trusted (not a wrong address)."""
    seen: set[int] = set()
    e: BaseException | None = exc
    while e is not None and id(e) not in seen:
        seen.add(id(e))
        if isinstance(e, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(e):
            return True
        e = e.__cause__ or e.__context__
    return False


def why(exc: Exception, url: str) -> str:
    """An exception in words, naming the real cause: an untrusted certificate, no connection, or a slow answer."""
    if isinstance(exc, httpx.ConnectError) and certificate_problem(exc):
        return (f"the connection to {url} was not trusted: something on this computer replaced the node's certificate "
                "(antivirus HTTPS scanning such as Norton, Avast or AVG, or a company proxy) with one this computer does "
                "not trust either. Exclude the node's address from that program's HTTPS scanning, or set SSL_CERT_FILE "
                "to its certificate")
    if isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout)):
        return f"could not reach {url} (check the Node Host URL, and that your node is on)"
    if isinstance(exc, httpx.TimeoutException):
        return f"{url} did not answer in time"
    return str(exc)


def status_tool(problem: str = "") -> dict:
    text = ("Checks the connection to your Vrymdor AI Node: says whether it is connected, with the node address, the "
            "agent and the tools it offers, or exactly what to fix.")
    if problem:
        text = f"Not connected to your Vrymdor AI Node yet: {problem}. Run this tool to check again. " + text
    return {"name": STATUS_TOOL, "title": "Vrymdor connection status", "description": text,
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            "annotations": {"title": "Vrymdor connection status", "readOnlyHint": True, "openWorldHint": False}}


def _reply(id_, result: dict) -> str:
    return json.dumps({"jsonrpc": "2.0", "id": id_, "result": result})


LIST_CHANGED = json.dumps({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})


class Bridge:
    def __init__(self, url: str, agent_id: str, secret: str, *, http: httpx.Client | None = None,
                 log: TextIO | None = None) -> None:
        self.url, self.agent_id, self._secret = clean_url(url), agent_id, secret
        self._owns_http = http is None
        self._http = http or self._new_client()
        self._token, self._expires = "", 0.0
        self._session = ""
        self.problem = ""   # why the node could not be reached last time; "" while it works
        self._tools: list[dict] = []   # the node's last good tool list, offered again if a later list fails
        self._log = log

    @staticmethod
    def _new_client() -> httpx.Client:
        return httpx.Client(timeout=httpx.Timeout(QUICK_SECONDS, connect=10.0), headers={"User-Agent": user_agent()},
                            verify=system_ssl_context())

    def _fresh_connection(self) -> None:
        """Drop pooled connections: a stalled one must not be reused for the retry."""
        if self._owns_http:
            try:
                self._http.close()
            except Exception:  # noqa: BLE001
                pass
            self._http = self._new_client()

    def _note(self, text: str) -> None:
        if self._log is not None:
            print(f"vrymdor-mcp: {text}", file=self._log, flush=True)

    def token(self) -> str:
        if self._token and time.time() < self._expires - 60:
            return self._token
        r = self._http.post(f"{self.url}/v1/token", json={"agent_id": self.agent_id, "agent_secret": self._secret},
                            timeout=httpx.Timeout(QUICK_SECONDS, connect=10.0))
        if r.status_code != 200:
            raise RuntimeError(refusal(r.status_code, r.content))
        doc = r.json()
        self._token, self._expires = doc["access_token"], time.time() + int(doc.get("expires_in", 600))
        return self._token

    def _send(self, line: str, method: str = "") -> httpx.Response:
        wait = CALL_SECONDS if method == "tools/call" else QUICK_SECONDS

        def post() -> httpx.Response:
            headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                       "Authorization": f"Bearer {self.token()}"}
            if self._session:
                headers["Mcp-Session-Id"] = self._session
            return self._http.post(f"{self.url}/mcp", content=line.encode("utf-8"), headers=headers,
                                   timeout=httpx.Timeout(wait, connect=10.0))

        started = time.monotonic()
        try:
            r = post()
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            if certificate_problem(exc):
                raise
            self._note(f"{method or 'request'}: no connection ({type(exc).__name__}), trying once more")
            self._fresh_connection()
            r = post()
        except RETRY_ERRORS as exc:
            # A tool call that may have reached the node is not sent twice, except a read only one.
            if method == "tools/call" and not line_is_read_only(line):
                raise
            self._note(f"{method or 'request'}: no answer after {time.monotonic() - started:.1f} s "
                       f"({type(exc).__name__}), trying once more on a fresh connection")
            self._fresh_connection()
            r = post()
        self._note(f"{method or 'request'} answered in {time.monotonic() - started:.1f} s")
        if r.status_code == 401:   # the token was revoked or the node restarted: get a fresh one and try once more
            self._token, self._expires = "", 0.0
            r = post()
        if r.headers.get("mcp-session-id"):
            self._session = r.headers["mcp-session-id"]
        return r

    def _node_tools(self) -> list[dict]:
        """The node's own tool list (raises on any failure, in words)."""
        r = self._send(json.dumps({"jsonrpc": "2.0", "id": "vrymdor-status", "method": "tools/list"}), "tools/list")
        text = r.content.decode("utf-8")
        if r.headers.get("content-type", "").split(";")[0].strip().lower() == "text/event-stream":
            text = sse_messages(text).split("\n")[0]
        doc = json.loads(text or "{}")
        if doc.get("error"):
            raise RuntimeError(str(doc["error"].get("message") or doc["error"]).rstrip("."))
        tools = [t for t in doc.get("result", {}).get("tools", []) if isinstance(t, dict)]
        if tools:
            self._tools = [t for t in tools if t.get("name") != STATUS_TOOL]
        return tools

    def status(self) -> tuple[bool, str, list[str]]:
        """Connected or not, in a sentence for a person, and the node's tool names."""
        try:
            self.token()
            names = [str(t.get("name")) for t in self._node_tools()]
        except (httpx.HTTPError, RuntimeError, ValueError, KeyError) as exc:
            self.problem = why(exc, self.url)
            return False, f"Not connected: {self.problem}.", []
        self.problem = ""
        if not names:
            return False, ("Connected, but the node listed no tools for this agent. Check the agent's role in your "
                           "policy."), []
        first = sorted(names, key=lambda n: (n != "vrymnox_sanitize", not n.startswith("vrymnox_"), n))[:4]
        return True, (f"Connected: your node at {self.url} accepted agent {self.agent_id} and offers {len(names)} "
                      f"tools, including {', '.join(first)}. Bridge vrymdor-mcp {version()}."), names

    def handle(self, line: str, err: TextIO = sys.stderr) -> str | None:
        try:
            msg = json.loads(line)
        except ValueError:
            return json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
        if not isinstance(msg, dict):
            return json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid request"}})
        has_id, method = "id" in msg, msg.get("method")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        if method == "tools/call" and params.get("name") == STATUS_TOOL:
            was_down = bool(self.problem)
            ok, text, _ = self.status()
            out = _reply(msg.get("id"), {"content": [{"type": "text", "text": text}], "isError": not ok})
            return f"{LIST_CHANGED}\n{out}" if ok and was_down else out
        try:
            r = self._send(line, str(method or ""))
        except (httpx.HTTPError, RuntimeError, ValueError, KeyError) as exc:
            self.problem = why(exc, self.url)
            print(f"vrymdor-mcp: {self.problem}", file=err, flush=True)
            return self._offline(msg, method, params, has_id)
        self.problem = ""
        if r.status_code == 202 or not r.content:
            return None   # a notification
        text = r.content.decode("utf-8")
        if r.headers.get("content-type", "").split(";")[0].strip().lower() == "text/event-stream":
            text = sse_messages(text)
        if method == "tools/list" and has_id:
            self._remember_tools(text, msg.get("id"))
            text = _with_status_tool(text, msg.get("id"))
        return text or None

    def _remember_tools(self, text: str, id_) -> None:
        for raw in text.split("\n"):
            try:
                doc = json.loads(raw)
            except ValueError:
                continue
            tools = doc.get("result", {}).get("tools") if isinstance(doc, dict) and doc.get("id") == id_ else None
            if isinstance(tools, list) and tools:
                self._tools = [t for t in tools if isinstance(t, dict) and t.get("name") != STATUS_TOOL]

    def _offline(self, msg: dict, method, params: dict, has_id: bool) -> str | None:
        """The node could not be reached: still start, so the client lists "vrymdor" with a tool that says why."""
        if not has_id:
            return None
        id_ = msg.get("id")
        if method == "initialize":
            return _reply(id_, {"protocolVersion": str(params.get("protocolVersion") or PROTOCOL),
                                "capabilities": {"tools": {"listChanged": True}},
                                "serverInfo": {"name": SERVER_KEY, "title": "Vrymdor AI Node", "version": version()},
                                "instructions": (f"Not connected to the Vrymdor AI Node yet: {self.problem}. The "
                                                 f"{STATUS_TOOL} tool checks again and says what to fix.")})
        if method == "tools/list":   # the last good list stays usable; the status tool says what is wrong right now
            return _reply(id_, {"tools": [*self._tools, status_tool(self.problem)]})
        if method == "ping":
            return _reply(id_, {})
        if method in ("resources/list", "prompts/list"):
            return _reply(id_, {method.split("/")[0]: []})
        return json.dumps({"jsonrpc": "2.0", "id": id_,
                           "error": {"code": -32603, "message": f"Your Vrymdor AI Node could not be reached: {self.problem}"}})


READ_ONLY_TOOLS = ("vrymnox_sanitize", "vrymnox_check", "vrymnox_hold_status")


def line_is_read_only(line: str) -> bool:
    """A tools/call that changes nothing anywhere, so sending it twice is harmless."""
    try:
        return json.loads(line).get("params", {}).get("name") in READ_ONLY_TOOLS
    except (ValueError, AttributeError):
        return False


def _with_status_tool(text: str, id_) -> str:
    """Add the vrymdor_status tool to the node's tool list answer (each line is one JSON message)."""
    out = []
    for raw in text.split("\n"):
        try:
            doc = json.loads(raw)
        except ValueError:
            out.append(raw)
            continue
        tools = doc.get("result", {}).get("tools") if isinstance(doc, dict) and doc.get("id") == id_ else None
        if isinstance(tools, list) and not any(isinstance(t, dict) and t.get("name") == STATUS_TOOL for t in tools):
            tools.append(status_tool())
            raw = json.dumps(doc)
        out.append(raw)
    return "\n".join(out)


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


def _utf8(stream: TextIO) -> None:
    # MCP messages are UTF-8 with \n line endings; a Windows console default (cp1252, \r\n) would damage them.
    try:
        stream.reconfigure(encoding="utf-8", newline="\n")   # type: ignore[attr-defined]
    except (AttributeError, ValueError):
        pass


def check(bridge: Bridge, out: TextIO = sys.stdout) -> int:
    """--check: get a token and list the tools, then say in words whether it works."""
    ok, text, _ = bridge.status()
    print(text, file=out)
    return 0 if ok else 1


# ---------------------------------------------------------------- Claude Desktop setup
def claude_config_paths(env: dict | None = None, platform: str | None = None, home: Path | None = None) -> list[Path]:
    """Every place Claude Desktop may read its settings from on this computer (the first one is always written).

    Windows: %APPDATA%\\Claude, and for the packaged (Microsoft Store style) install also its own folder under
    %LOCALAPPDATA%\\Packages. macOS: ~/Library/Application Support/Claude. Linux: ~/.config/Claude."""
    env = os.environ if env is None else env
    platform = platform or sys.platform
    home = home or Path.home()
    name = "claude_desktop_config.json"
    if platform.startswith("win"):
        out = [Path(env.get("APPDATA") or home / "AppData" / "Roaming") / "Claude" / name]
        packages = Path(env.get("LOCALAPPDATA") or home / "AppData" / "Local") / "Packages"
        if packages.is_dir():
            out += [d / "LocalCache" / "Roaming" / "Claude" / name for d in sorted(packages.glob("Claude_*")) if d.is_dir()]
        return out
    if platform == "darwin":
        return [home / "Library" / "Application Support" / "Claude" / name]
    return [Path(env.get("XDG_CONFIG_HOME") or home / ".config") / "Claude" / name]


def _ephemeral(path: str) -> bool:
    """A command inside uv's cache (what uvx runs) moves on the next update: never write that into Claude's settings."""
    parts = [p.lower() for p in path.replace("\\", "/").split("/")]
    return any(p in ("cache", ".cache") or p.startswith("archive-v") for p in parts)


def installed_command(env: dict | None = None, home: Path | None = None) -> str:
    """The lasting vrymdor-mcp command (uv tool install vrymdor-node puts it in ~/.local/bin), or "" when there is none."""
    env = os.environ if env is None else env
    home = home or Path.home()
    exe = "vrymdor-mcp.exe" if os.name == "nt" else "vrymdor-mcp"
    candidates = [env.get("UV_TOOL_BIN_DIR", ""), env.get("XDG_BIN_HOME", ""), str(home / ".local" / "bin")]
    found = [shutil.which("vrymdor-mcp") or ""] + [str(Path(d) / exe) for d in candidates if d]
    for c in found:
        if c and Path(c).is_file() and not _ephemeral(c):
            return str(Path(c))
    return ""


def server_entry(url: str, agent_id: str, secret: str, command: str = "") -> dict:
    """Claude Desktop's settings for this server: the installed command, or uvx told to use the computer's certificates."""
    env = {"VRYMNOX_NODE_URL": clean_url(url), "VRYMNOX_AGENT_ID": agent_id, "VRYMNOX_AGENT_SECRET": secret}
    if command:
        return {"command": command, "args": [], "env": env}
    uvx = shutil.which("uvx") or "uvx"
    # uv downloads with its own certificate list unless told otherwise: UV_SYSTEM_CERTS (uv 0.11 and later) and
    # UV_NATIVE_TLS (earlier versions) make it use the computer's, as antivirus HTTPS scanning needs.
    return {"command": uvx, "args": ["--from", "vrymdor-node", "vrymdor-mcp"],
            "env": {**env, "UV_SYSTEM_CERTS": "true", "UV_NATIVE_TLS": "true"}}


def write_claude_config(path: Path, entry: dict) -> Path | None:
    """Put the vrymdor server into one settings file, keeping everything else in it. Returns the backup, if any."""
    doc: dict = {}
    backup = None
    if path.is_file():
        raw = path.read_text(encoding="utf-8-sig")
        backup = path.with_name(f"{path.name}.{datetime.now().strftime('%Y%m%d-%H%M%S')}.bak")
        backup.write_text(raw, encoding="utf-8")
        try:
            loaded = json.loads(raw) if raw.strip() else {}
            doc = loaded if isinstance(loaded, dict) else {}
        except ValueError:
            doc = {}   # damaged: the backup keeps the old text, the new file starts clean
    servers = doc.get("mcpServers") if isinstance(doc.get("mcpServers"), dict) else {}
    servers[SERVER_KEY] = entry
    doc["mcpServers"] = servers
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")   # UTF-8 without a byte order mark
    return backup


def as_claude_would(entry: dict, timeout: float = 55.0) -> tuple[bool, str]:
    """Run the exact command written into Claude's settings and do what Claude does first: initialize, then list the
    tools, within Claude's 60 second limit. Returns whether the tools came back, in words."""
    lines = [{"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
                 "protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": "vrymdor-setup", "version": version()}}},
             {"jsonrpc": "2.0", "method": "notifications/initialized"},
             {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}]
    started = time.monotonic()
    try:
        proc = subprocess.run([entry["command"], *entry.get("args", [])], input="".join(json.dumps(m) + "\n" for m in lines),
                              capture_output=True, text=True, encoding="utf-8", timeout=timeout,
                              env={**os.environ, **entry.get("env", {})})
    except subprocess.TimeoutExpired:
        return False, f"it did not answer within {timeout:.0f} seconds, so Claude Desktop would give up"
    except OSError as exc:
        return False, f"it could not be started ({exc})"
    took = time.monotonic() - started
    answers = {}
    for raw in proc.stdout.splitlines():
        try:
            doc = json.loads(raw)
        except ValueError:
            continue
        if isinstance(doc, dict) and "id" in doc:
            answers[doc["id"]] = doc
    tools = [t.get("name") for t in answers.get(1, {}).get("result", {}).get("tools", []) if isinstance(t, dict)]
    node_tools = [n for n in tools if n != STATUS_TOOL]
    if node_tools:
        return True, f"it started and listed {len(tools)} tools in {took:.1f} seconds"
    if tools:
        desc = str(answers[1]["result"]["tools"][-1].get("description", ""))
        reason = desc.split("yet: ", 1)[-1].split(". Run this tool", 1)[0] if "yet: " in desc else desc
        return False, f"it started in {took:.1f} seconds but lists only {STATUS_TOOL}, because {reason[:300]}"
    last = (proc.stderr.strip().splitlines() or ["no answer"])[-1]
    return False, f"it did not list any tools ({last[:300]})"


def restart_claude(platform: str | None = None) -> str:
    """Close Claude Desktop and open it again so it reads the new settings. Returns what happened, in words."""
    platform = platform or sys.platform
    try:
        if platform.startswith("win"):
            # Close it if it runs, then open it from its Start menu entry (works for the installer and the packaged
            # install alike); the path of the running copy is the fallback.
            ps = ("$p = Get-Process claude -ErrorAction SilentlyContinue; $path = ($p | Where-Object Path | "
                  "Select-Object -First 1).Path; if ($p) { $p | Stop-Process -Force; Start-Sleep -Seconds 2 }; "
                  "$app = Get-StartApps -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Claude' } | "
                  "Select-Object -First 1; if ($app) { Start-Process \"shell:AppsFolder\\$($app.AppID)\"; 'restarted' } "
                  "elseif ($path) { Start-Process $path; 'restarted' } elseif ($p) { 'closed' } else { 'not running' }")
            out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True,
                                 timeout=30).stdout.strip().splitlines()
            return out[-1] if out else "closed"
        if platform == "darwin":
            running = subprocess.run(["pgrep", "-x", "Claude"], capture_output=True).returncode == 0
            if not running:
                return "not running"
            subprocess.run(["osascript", "-e", 'quit app "Claude"'], capture_output=True, timeout=30)
            time.sleep(2)
            subprocess.run(["open", "-a", "Claude"], capture_output=True, timeout=30)
            return "restarted"
    except (OSError, subprocess.SubprocessError):
        return "closed"
    return "not running"


def _ask(prompt: str, secret: bool = False) -> str:
    if not sys.stdin or not sys.stdin.isatty():
        return ""
    if secret:
        import getpass

        return getpass.getpass(prompt).strip()
    return input(prompt).strip()


def install_claude(args: list[str], out: TextIO = sys.stdout, bridge: Bridge | None = None) -> int:
    """--install-claude: test the agent, then write Claude Desktop's settings and restart it."""
    url = setting("url") or _ask("Node Host URL (from AI agents, Connect your AI Node): ")
    agent_id = setting("id") or _ask("Agent ID (agt_...): ")
    secret = setting("secret") or _ask("Agent Secret (vrym_agent_..., hidden as you type): ", secret=True)
    if not (url and agent_id and secret):
        print("Not set up: give the Node Host URL, the Agent ID and the Agent Secret (VRYMNOX_NODE_URL, "
              "VRYMNOX_AGENT_ID, VRYMNOX_AGENT_SECRET).", file=out)
        return 2
    url = clean_url(url)
    if not url.startswith(("http://", "https://")):
        print("Not set up: the Node Host URL must start with https:// (or http:// for a node on this computer).", file=out)
        return 2
    ok, text, _ = (bridge or Bridge(url, agent_id, secret)).status()
    print(f"1. Testing your agent. {text}", file=out)
    if not ok and "--force" not in args:
        print("Claude Desktop was not changed. Fix the line above and run this again.", file=out)
        return 1
    command = installed_command()
    entry = server_entry(url, agent_id, secret, command)
    paths = claude_config_paths()
    for path in paths:
        backup = write_claude_config(path, entry)
        print(f"2. Claude Desktop settings written: {path}" + (f" (your old file is kept as {backup.name})" if backup else ""),
              file=out)
    if not command:
        print("   It starts the bridge with uvx. For a faster start that never downloads, run "
              "'uv tool install vrymdor-node' and then this command again.", file=out)
    if "--no-simulate" not in args:
        worked, what = as_claude_would(entry)
        print(f"3. Running it the way Claude Desktop will: {what}.", file=out)
        if not worked:
            print("   Claude Desktop will list vrymdor, and its vrymdor_status tool will say what is wrong.", file=out)
    state = "skipped" if "--no-restart" in args else restart_claude()
    if state == "restarted":
        print("4. Claude Desktop was restarted so it reads the new settings.", file=out)
    elif state == "closed":
        print("4. Claude Desktop was closed. Open it again.", file=out)
    else:
        print("4. Open Claude Desktop (if it is open, quit it completely from its icon by the clock, then open it).",
              file=out)
    print("Done. In Claude Desktop, click + next to the message box, then Connectors: vrymdor is listed. "
          "To confirm, ask Claude: \"run vrymdor_status\". It answers Connected, with your node and agent.", file=out)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if "--version" in args:
        print(f"vrymdor-mcp {version()}")
        return 0
    if "-h" in args or "--help" in args:
        print(__doc__)
        return 0
    if "--install-claude" in args or "setup" in args:
        return install_claude(args)
    missing = [NAMES[k][0] for k in ("url", "id", "secret") if not setting(k)]
    if missing:
        print(f"vrymdor-mcp: set {', '.join(missing)} (in your MCP client's env block)", file=sys.stderr)
        return 2
    url = setting("url")
    if not url.startswith(("http://", "https://")):
        print("vrymdor-mcp: VRYMNOX_NODE_URL must start with https:// (or http:// for a node on this computer)",
              file=sys.stderr)
        return 2
    if "--check" in args:
        return check(Bridge(url, setting("id"), setting("secret")))
    bridge = Bridge(url, setting("id"), setting("secret"), log=sys.stderr)   # timings go to the client's log
    _utf8(sys.stdin)
    _utf8(sys.stdout)
    try:
        for line in sys.stdin:
            if line.strip():
                out = bridge.handle(line.strip())
                if out is not None:
                    sys.stdout.write(out + "\n")
                    sys.stdout.flush()
    except (KeyboardInterrupt, BrokenPipeError):
        pass
    except OSError:
        pass   # the client closed the connection (Windows reports it as Invalid argument): nothing left to answer
    try:
        sys.stdout.flush()
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
