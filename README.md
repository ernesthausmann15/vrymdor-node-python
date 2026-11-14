# vrymdor-node

The Python client for the Vrymdor AI Node by Vrymnox Systems LLC. Every call goes through your node's
checks: the agent's identity and status, your policy, removal of PII (personally identifiable information)
and secrets, a signed request and a metadata-only audit record. One module, one dependency (httpx).

## Install

```bash
pip install vrymdor-node                 # the client
pip install "vrymdor-node[langchain]"    # plus LangChain tools
pip install "vrymdor-node[llamaindex]"   # plus LlamaIndex tools
```

## Use

You need your node's address and an agent registered in the Vrymdor app (AI agents, Register an agent).
The agent secret is shown once.

```python
from vrymnox_node import VrymnoxNode

node = VrymnoxNode("http://vrymdor-node:8080", agent_id="agt_...", agent_secret="vrym_agent_...")

node.sanitize("Customer jane@acme.io called")         # "Customer [REDACTED:EMAIL] called"
node.tool("github", "create_issue", {"title": "Login fails"})
node.llm("anthropic", "v1/messages", {"model": "...", "messages": [...]})

tools = node.langchain_tools()     # one LangChain StructuredTool per tool your policy allows
tools = node.llamaindex_tools()    # the same, as LlamaIndex FunctionTools
```

A refusal raises `VrymnoxError` with a stable `code` (for example `tool_not_allowed`, `rate_limited`,
`agent_stopped`) and `retryable`. An action your policy holds raises `VrymnoxHeld` (code
`held_by_policy`): it did not run, and a held action is never released. Change the policy to allow it.

Documentation: https://docs.vrymdor.com/ai-node.html

## MCP: Claude Desktop, Cursor and VS Code, no Docker

<!-- mcp-name: io.github.ernesthausmann15/vrymdor-mcp -->

The package includes `vrymdor-mcp`, the bridge desktop MCP clients start as a local command. It relays each MCP
message to your node and renews the agent's token by itself. The easiest way to run it is `uvx`, which also fetches
a matching Python for you: install uv once (macOS and Linux: `curl -LsSf https://astral.sh/uv/install.sh | sh`;
Windows PowerShell: `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"`).

### Claude Desktop in one command

It tests your agent, writes Claude Desktop's settings in the right place (keeping a backup of the old file) and
restarts Claude Desktop. Use the three values from AI agents, Connect your AI Node.

Windows (PowerShell):

```powershell
$env:UV_SYSTEM_CERTS="true"; $env:UV_NATIVE_TLS="true"; $env:VRYMNOX_NODE_URL="https://node.vrymdor.com/t/abc123def456"; $env:VRYMNOX_AGENT_ID="agt_..."; $env:VRYMNOX_AGENT_SECRET="vrym_agent_..."; uv tool install --force "vrymdor-node>=1.2"; uvx --from "vrymdor-node>=1.2" vrymdor-mcp --install-claude
```

macOS and Linux:

```bash
export UV_SYSTEM_CERTS=true UV_NATIVE_TLS=true VRYMNOX_NODE_URL=https://node.vrymdor.com/t/abc123def456 \
  VRYMNOX_AGENT_ID=agt_... VRYMNOX_AGENT_SECRET=vrym_agent_...
uv tool install --force "vrymdor-node>=1.2" && uvx --from "vrymdor-node>=1.2" vrymdor-mcp --install-claude
```

Then in Claude Desktop click **+** next to the message box, then **Connectors**: **vrymdor** is listed. Ask Claude
"run vrymdor_status" to confirm: it answers Connected, with your node and agent, or says exactly what to fix.

`UV_SYSTEM_CERTS` and `UV_NATIVE_TLS` make uv download with the computer's own certificates, which antivirus HTTPS
scanning (Norton, Avast, AVG) and company proxies need. The bridge itself always trusts the computer's certificates.

### Test the agent

It prints "Connected: ..." or the reason it is not:

```bash
VRYMNOX_NODE_URL=https://node.vrymdor.com/t/abc123def456 VRYMNOX_AGENT_ID=agt_... \
  VRYMNOX_AGENT_SECRET=vrym_agent_... uvx --from vrymdor-node vrymdor-mcp --check
```

### Settings by hand: Cursor, VS Code, or Claude Desktop

Cursor (`mcp.json`) and Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "vrymdor": {
      "command": "uvx",
      "args": ["--from", "vrymdor-node", "vrymdor-mcp"],
      "env": {
        "VRYMNOX_NODE_URL": "https://node.vrymdor.com/t/abc123def456",
        "VRYMNOX_AGENT_ID": "agt_...",
        "VRYMNOX_AGENT_SECRET": "vrym_agent_...",
        "UV_SYSTEM_CERTS": "true",
        "UV_NATIVE_TLS": "true"
      }
    }
  }
}
```

VS Code (`.vscode/mcp.json`): the same block under `"servers"`, with `"type": "stdio"` added.

If the client says it cannot find `uvx` (Claude Desktop on macOS starts commands without your shell's PATH), put
the full path in `command`: the output of `which uvx` (macOS, Linux) or `where.exe uvx` (Windows).

The client always lists **vrymdor**, even when the node cannot be reached: its `vrymdor_status` tool then says why.

## License

MIT. The Vrymdor AI Node itself is licensed separately under your Vrymnox agreement.

## License and terms

Copyright (c) 2026 Vrymnox Systems LLC. This client is open source under the MIT License (LICENSE). Using the
Vrymdor AI Node service it connects to is governed by the Vrymdor Master Subscription Agreement
(https://vrymdor.com/msa) and the Acceptable Use Policy in the agreement set you accept when you sign up.
