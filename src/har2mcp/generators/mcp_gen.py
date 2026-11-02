"""Bundle compiler that writes evidence-model.json, cassette.json, openapi.json, sdk.ts, and mcp_server.py."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from har2mcp.generators.openapi_gen import generate_openapi_31_spec
from har2mcp.generators.sdk_gen import generate_typescript_sdk
from har2mcp.graphql import extract_graphql_operations
from har2mcp.inference import build_intermediate_api_model
from har2mcp.limits import DEFAULT_LIMITS, HarProcessingLimits
from har2mcp.sanitizer import parse_and_sanitize_har_file


MCP_SERVER_ENTRYPOINT_TEMPLATE = '#!/usr/bin/env python3\n"""Generated offline MCP entry point. Install har2mcp first."""\nimport argparse\nimport asyncio\nfrom pathlib import Path\nfrom har2mcp.mcp_runtime import load_dispatcher_from_directory, run_stdio_mcp_server\ndef main():\n    parser = argparse.ArgumentParser(description="Run an offline har2mcp MCP bundle")\n    parser.add_argument("--mode", choices=["cassette", "simulated-state"], default="cassette")\n    args = parser.parse_args()\n    dispatcher = load_dispatcher_from_directory(Path(__file__).resolve().parent, mode=args.mode)\n    asyncio.run(run_stdio_mcp_server(dispatcher))\nif __name__ == "__main__":\n    main()\n'

def compile_har_to_directory(
    har_path: str | Path,
    output_dir: str | Path,
    title: str = "HAR-Inferred API Surface",
    include_graphql: bool = False,
    limits: HarProcessingLimits = DEFAULT_LIMITS,
) -> dict[str, Any]:
    """Sanitize a HAR file and compile all target artifacts into output_dir."""
    out = Path(output_dir).resolve()
    if out.exists():
        raise FileExistsError("Output directory already exists; choose a new directory")

    capture = parse_and_sanitize_har_file(har_path, limits=limits)
    model, cassette = build_intermediate_api_model(capture, limits=limits)
    openapi_spec = generate_openapi_31_spec(model, title=title)
    ts_sdk = generate_typescript_sdk(model)

    out.mkdir(parents=True, exist_ok=False)
    model_file = out / "evidence-model.json"
    cassette_file = out / "cassette.json"
    openapi_file = out / "openapi.json"
    sdk_file = out / "sdk.ts"
    server_file = out / "mcp_server.py"
    env_example_file = out / ".env.example"

    model_file.write_text(
        json.dumps(model.model_dump(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    cassette_file.write_text(
        json.dumps(cassette.model_dump(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    openapi_file.write_text(
        json.dumps(openapi_spec, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    sdk_file.write_text(ts_sdk, encoding="utf-8")
    server_file.write_text(MCP_SERVER_ENTRYPOINT_TEMPLATE, encoding="utf-8")

    env_lines = [
        "# Observed authentication hints only; this offline release never uses credentials.",
        "# Never commit real credentials to version control.",
    ]
    for env_key, env_desc in sorted(model.redaction_summary.required_env_vars.items()):
        description = env_desc.replace("\r", " ").replace("\n", " ")
        env_lines.append(f"# {description}")
        env_lines.append(f"{env_key}=")
    env_example_file.write_text("\n".join(env_lines) + "\n", encoding="utf-8")

    written_files = [
        str(model_file),
        str(cassette_file),
        str(openapi_file),
        str(sdk_file),
        str(server_file),
        str(env_example_file),
    ]

    graphql_count = 0
    if include_graphql:
        gql_ops = extract_graphql_operations(capture, limits=limits)
        graphql_count = len(gql_ops)
        gql_file = out / "graphql-operations.json"
        gql_file.write_text(
            json.dumps([op.model_dump() for op in gql_ops], indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        written_files.append(str(gql_file))

    return {
        "source_filename": capture.source_filename,
        "output_directory": str(out),
        "primary_origin": model.primary_origin,
        "endpoint_count": len(model.endpoints),
        "cassette_entry_count": len(cassette.entries),
        "excluded_entry_count": len(capture.excluded_entries),
        "graphql_operation_count": graphql_count,
        "redaction_summary": model.redaction_summary.model_dump(),
        "written_files": written_files,
    }
