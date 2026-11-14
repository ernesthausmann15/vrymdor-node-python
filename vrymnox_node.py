"""Vrymnox AI Node client for Python apps and agent frameworks (one file; needs only httpx).

    from vrymnox_node import VrymnoxNode
    node = VrymnoxNode("http://vrymnox-gateway:8080", agent_id="agt_...", agent_secret="vrym_agent_...")
    node.sanitize("Customer jane@acme.io called")            # -> "Customer [REDACTED:EMAIL] called"
    node.tool("github", "create_issue", {"title": "Login fails"})
    node.llm("anthropic", "v1/messages", {"model": "...", "messages": [...]})

    # LangChain: every tool the agent's policy allows, as governed LangChain tools
    tools = node.langchain_tools()
    # LlamaIndex: the same, as FunctionTools
    tools = node.llamaindex_tools()

Every call goes through the gateway's checks (identity, policy, redaction, audit). A refusal raises
VrymnoxError with a stable `code` (tool_not_allowed, rate_limited, agent_stopped, ...) and `retryable`.
"""
from __future__ import annotations

import os
import ssl
import time
import uuid
from typing import Any

import httpx


def system_ssl_context() -> ssl.SSLContext | bool:
    """Trust the certificates this computer trusts (the Windows, macOS or Linux certificate store), as a browser does.

    Antivirus HTTPS scanning (Norton, Avast, AVG and others) and company proxies replace a site's certificate with their
    own, which the computer trusts but Python's bundled list does not: without this, every call to the node fails with a
    certificate error on those machines. SSL_CERT_FILE or SSL_CERT_DIR, when set, keep their usual meaning."""
    if os.environ.get("SSL_CERT_FILE") or os.environ.get("SSL_CERT_DIR"):
        return True
    try:
        import truststore

        return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    except Exception:  # noqa: BLE001 (truststore missing or the platform store unreadable: Python's own list)
        return True


class VrymnoxError(Exception):
    def __init__(self, code: str, message: str, retryable: bool = False, response: dict | None = None) -> None:
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.retryable, self.response = code, message, retryable, response or {}


class VrymnoxHeld(VrymnoxError):
    """Your policy held the action, so it did not run. Holds are final; `hold_id` is kept for the audit."""

    def __init__(self, hold_id: str, response: dict) -> None:
        super().__init__("held_by_policy", "Your policy holds this action, so it did not run.", False, response)
        self.hold_id = hold_id


class VrymnoxNode:
    def __init__(self, url: str, *, agent_id: str, agent_secret: str, http: httpx.Client | None = None,
                 timeout: float = 120.0) -> None:
        self.url, self.agent_id, self._secret = url.rstrip("/"), agent_id, agent_secret
        # Our own name: Cloudflare's browser check in front of a hosted node can refuse stock library names.
        self._http = http or httpx.Client(timeout=timeout, headers={"User-Agent": "vrymdor-node-python"},
                                          verify=system_ssl_context())
        self._token, self._expires = "", 0.0

    # ------------------------------------------------------------ plumbing
    def _auth(self) -> dict:
        if time.time() >= self._expires - 60:
            r = self._http.post(f"{self.url}/v1/token", json={"agent_id": self.agent_id, "agent_secret": self._secret})
            if r.status_code != 200:
                raise VrymnoxError("unauthenticated", "The gateway refused this agent's credential.")
            doc = r.json()
            self._token, self._expires = doc["access_token"], time.time() + int(doc.get("expires_in", 600))
        return {"Authorization": f"Bearer {self._token}"}

    def run(self, action: dict, input: Any = None, *, context: dict | None = None, dry_run: bool = False,
            idempotency_key: str | None = None) -> dict:
        """The raw NodeRequest call. Returns the NodeResponse; raises on refusal or hold."""
        body = {"node_version": "1", "action": action, "input": input, "context": context or {},
                "params": {"dry_run": dry_run}, "idempotency_key": idempotency_key or uuid.uuid4().hex}
        out = self._http.post(f"{self.url}/v1/node/run", json=body, headers=self._auth()).json()
        return self._result(out)

    @staticmethod
    def _result(out: dict) -> dict:
        if out.get("decision") == "hold":
            raise VrymnoxHeld(out["hold_id"], out)
        if not out.get("ok"):
            err = out.get("error") or {}
            raise VrymnoxError(err.get("code", "error"), err.get("message", "The action was refused."),
                               bool(err.get("retryable")), out)
        return out

    def wait_for(self, hold_id: str, *, timeout: float = 900, every: float = 5) -> dict:
        """The final answer for a held action. Holds are final, so it answers at once: the action did not run
        (VrymnoxError held_by_policy). Kept so existing code keeps working."""
        end = time.time() + timeout
        while time.time() < end:
            r = self._http.get(f"{self.url}/v1/node/holds/{hold_id}", headers=self._auth())
            if r.status_code != 202:
                return self._result(r.json())
            time.sleep(every)
        raise VrymnoxError("held_by_policy", "Your policy holds this action, so it did not run.", False)

    # ------------------------------------------------------------ the four actions
    def sanitize(self, value: Any) -> Any:
        return self.run({"type": "sanitize"}, value)["output"]

    def tool(self, upstream: str, tool: str, arguments: dict | None = None, **kw) -> Any:
        return self.run({"type": "tool", "upstream": upstream, "tool": tool}, arguments or {}, **kw)["output"]

    def llm(self, upstream: str, path: str, body: dict, **kw) -> Any:
        return self.run({"type": "llm", "upstream": upstream, "path": path}, body, **kw)["output"]

    def webhook(self, upstream: str, payload: Any, **kw) -> Any:
        return self.run({"type": "webhook", "upstream": upstream}, payload, **kw)["output"]

    # ------------------------------------------------------------ framework adapters
    def governed_tools(self) -> list[dict]:
        """The tools this agent may call, from the gateway's MCP tool list (policy decides; nothing is guessed)."""
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        tools = self._http.post(f"{self.url}/mcp", json=msg, headers=self._auth()).json()["result"]["tools"]
        return [t for t in tools if "__" in t["name"]]

    def _caller(self, name: str):
        upstream, tool = name.split("__", 1)

        def call(**arguments: Any) -> Any:
            return self.tool(upstream, tool, arguments)
        return call

    def langchain_tools(self) -> list:
        from langchain_core.tools import StructuredTool  # optional dependency

        return [StructuredTool.from_function(func=self._caller(t["name"]), name=t["name"], description=t["description"],
                                             args_schema=t["inputSchema"]) for t in self.governed_tools()]

    def llamaindex_tools(self) -> list:
        from llama_index.core.tools import FunctionTool  # optional dependency

        return [FunctionTool.from_defaults(fn=self._caller(t["name"]), name=t["name"], description=t["description"],
                                           fn_schema=_json_schema_model(t["name"], t.get("inputSchema") or {}))
                for t in self.governed_tools()]


def _json_schema_model(name: str, schema: dict):
    """A pydantic model that reports the gateway's JSON Schema as is. LlamaIndex reads a tool's arguments from
    fn_schema; without it the model would only see the caller's generic **arguments. Extra fields are allowed
    because the gateway, not this model, validates the arguments (tool_schema rule)."""
    from pydantic import BaseModel, ConfigDict

    published = {"type": "object", "properties": {}, **schema}

    class ToolArguments(BaseModel):
        model_config = ConfigDict(extra="allow")

        @classmethod
        def model_json_schema(cls, *args: Any, **kwargs: Any) -> dict:
            return dict(published)

    ToolArguments.__name__ = ToolArguments.__qualname__ = "".join(p.title() for p in name.split("_") if p) or "Tool"
    return ToolArguments
