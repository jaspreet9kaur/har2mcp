# har2mcp

Turn an authorized browser network recording into an **offline API exploration kit**: observed endpoint documentation, a recorded-response client, and an MCP server for AI-assisted inspection.

**Early alpha: 0.1.0a1.** Live HTTP is intentionally unavailable in this release. This tool does not reconstruct a backend or prove that a captured API contract is complete. There are no claimed users, adoption metrics or sponsorship approvals.

## Who is it for?

- Developers exploring an API they own or are authorized to inspect.
- Testers who need local recorded responses without calling the original service.
- MCP developers prototyping an integration from a synthetic or approved recording.

## Install from source

Requires Python 3.11+. No Claude subscription or API key is needed. The package is distributed from this GitHub repository; no PyPI publication is claimed.

```sh
git clone https://github.com/jaspreet9kaur/har2mcp.git
cd har2mcp
python -m venv .venv
```

Activate the virtual environment:

```sh
# Linux / macOS
. .venv/bin/activate
```

```powershell
# Windows PowerShell: use its Python directly; no activation-policy changes needed
.venv\Scripts\python.exe -m pip install .
.venv\Scripts\python.exe -m har2mcp --help
```

On Linux/macOS, install with `python -m pip install .`. For the examples below, use the virtual environment's Python (or `.venv\Scripts\python.exe` on Windows). Installation downloads dependencies; processing a capture and replaying it are offline.

## Try the synthetic example

```sh
python -m har2mcp inspect tests/fixtures/sample_api.synthetic.har --include-graphql
python -m har2mcp compile tests/fixtures/sample_api.synthetic.har --out demo-bundle --include-graphql
python -m har2mcp serve demo-bundle --mode cassette
```

Choose a **new** output directory each time. Compilation refuses an existing directory. The stdio server waits for an MCP client; it is not an HTTP website. Stop it with Ctrl+C when finished.

## Generated files

| File | Purpose |
| --- | --- |
| evidence-model.json | Observed endpoints, route guesses, source record numbers and limitations |
| cassette.json | Sanitized recorded requests/responses for offline matching |
| openapi.json | OpenAPI 3.1-shaped documentation inferred from the samples |
| sdk.ts | Standalone TypeScript client for offline cassette replay |
| mcp_server.py | Entry point using the installed official Python MCP SDK |
| .env.example | Blank authentication hints observed in the recording; unused by this offline version |
| graphql-operations.json | Optional GraphQL operation evidence and inferred schemas |

The generated server depends on the installed `har2mcp` package. It is not a standalone executable. The TypeScript client accepts the records in `cassette.json` through its `cassetteEntries` option; it does not load files or contact a server automatically.

## Connect an MCP client

For a client that accepts a stdio command configuration:

```json
{
  "mcpServers": {
    "har2mcp-demo": {
      "command": "/absolute/path/to/har2mcp/.venv/bin/python",
      "args": ["-m", "har2mcp", "serve", "/absolute/path/to/demo-bundle", "--mode", "cassette"]
    }
  }
}
```

Replace both paths with your own; on Windows use the `.venv\\Scripts\\python.exe` path with JSON-escaped backslashes. Configuration layouts differ by client. Returned captured content is untrusted data, not instructions for the assistant to obey.

## Replay and simulation

Default replay requires matching origin, method, tool, path, query and parsed request body. If no recorded request matches, it returns `matched: false` and a local 404 result. Repeated identical requests select the earliest recorded response. No live request is sent, and recorded POST/DELETE responses do not change server state.

`--mode simulated-state` is an optional, heuristic in-memory CRUD experiment. Every response is labeled `simulated-in-memory`. Its collection grouping is simplistic and does not reproduce backend authorization, persistence, nesting, validation or business rules. Use cassette mode when fidelity to recorded requests matters.

## Other commands

```sh
python -m har2mcp sanitize approved.har --out sanitized.json
python -m har2mcp diff old.har new.har
```

An endpoint absent from a second capture is reported as **unobserved**, not proven deleted. Origins are kept distinct. Captures with conflicting method/path combinations across origins must be split before OpenAPI compilation; they are not silently overwritten.

## Privacy and limits

Use synthetic data for shared examples. HAR files can contain session cookies, API keys, personal records, signed URLs and secrets embedded in paths, ordinary-looking strings or GraphQL text. Heuristic redaction removes known patterns and sensitive field names; it **does not guarantee a shareable or anonymized artifact**. Review every generated file before sharing. Never commit real captures or use privileged production sessions for demonstrations.

Input limits include 50 MiB per HAR, 5,000 exchanges, 2 MiB bodies, bounded JSON nesting and 32 path segments. These are parser bounds, not a hard memory guarantee on your machine. HTML, multipart, binary/base64 and unsupported bodies are withheld. Route and schema inference remain guesses from finite samples. Review [SECURITY.md](SECURITY.md) and [the baseline review](docs/SECURITY-REVIEW.md).

## Tests and contribution

See [CONTRIBUTING.md](CONTRIBUTING.md) for the reproducible isolated checks. The CI container blocks network access during test/build execution, mounts source read-only, starts with an explicit environment and limits CPU, memory, processes, files and scratch disk. Image/dependency provisioning occurs separately with network access. A Python socket monkeypatch is not treated as OS isolation.

Open a [bug report](https://github.com/jaspreet9kaur/har2mcp/issues/new/choose) using a **minimal synthetic fixture**. Useful contributions include inference false-positive fixes, better sanitization tests and clearer examples. See [the roadmap](docs/ROADMAP.md).

## License and provenance

MIT; existing notices are preserved. The user's original local implementation was adapted for this public alpha. `morluto/rea` was a conceptual reference reported by that implementation; this publication does not claim a new upstream code audit or inherit another project's adoption. See [provenance](docs/PROVENANCE.md).
