"""Command-line interface for har2mcp."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import click

from har2mcp.diff import diff_intermediate_models
from har2mcp.generators.mcp_gen import compile_har_to_directory
from har2mcp.graphql import extract_graphql_operations
from har2mcp.inference import build_intermediate_api_model
from har2mcp.mcp_runtime import load_dispatcher_from_directory, run_stdio_mcp_server
from har2mcp.sanitizer import parse_and_sanitize_har_file


@click.group(
    help="har2mcp: Sanitize HAR captures and compile them into OpenAPI 3.1, typed SDKs, and official-SDK stdio MCP servers."
)
def main() -> None:
    pass


@main.command("inspect")
@click.argument("har_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--include-graphql", is_flag=True, help="Include separately scoped GraphQL operation analysis")
def inspect_cmd(har_path: Path, include_graphql: bool) -> None:
    """Inspect a HAR capture offline and print sanitized API surface summary as JSON."""
    capture = parse_and_sanitize_har_file(har_path)
    model, _ = build_intermediate_api_model(capture)
    payload = {
        "source_filename": capture.source_filename,
        "total_raw_entries": capture.total_raw_entries,
        "admitted_exchange_count": len(capture.admitted_exchanges),
        "excluded_entry_count": len(capture.excluded_entries),
        "primary_origin": model.primary_origin,
        "all_origins": model.all_origins,
        "endpoints": [
            {
                "tool_name": ep.tool_name,
                "method": ep.method,
                "origin": ep.origin,
                "path_template": ep.path_template,
                "route_confidence": ep.route_confidence,
                "observed_path_variants": ep.observed_path_variants,
                "evidence_ordinals": ep.evidence_ordinals,
            }
            for ep in model.endpoints
        ],
        "redaction_summary": model.redaction_summary.model_dump(),
        "epistemic_limits": model.epistemic_limits,
    }
    if include_graphql:
        gql_ops = extract_graphql_operations(capture)
        payload["graphql_operations"] = [op.model_dump() for op in gql_ops]
    click.echo(json.dumps(payload, indent=2, ensure_ascii=False))


@main.command("sanitize")
@click.argument("har_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--out", "out_path", required=True, type=click.Path(dir_okay=False, path_type=Path))
def sanitize_cmd(har_path: Path, out_path: Path) -> None:
    """Sanitize a HAR file and write the scrubbed SanitizedHarCapture JSON."""
    capture = parse_and_sanitize_har_file(har_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(capture.model_dump(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    click.echo(
        json.dumps(
            {
                "sanitized_output": str(out_path.resolve()),
                "admitted_exchanges": len(capture.admitted_exchanges),
                "excluded_entries": len(capture.excluded_entries),
                "redaction_summary": capture.redaction_summary.model_dump(),
            },
            indent=2,
        )
    )


@main.command("compile")
@click.argument("har_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--out", "out_dir", required=True, type=click.Path(file_okay=False, path_type=Path))
@click.option("--title", default="HAR-Inferred API Surface", help="OpenAPI specification title")
@click.option("--include-graphql", is_flag=True, help="Also emit graphql-operations.json")
def compile_cmd(har_path: Path, out_dir: Path, title: str, include_graphql: bool) -> None:
    """Compile a HAR file into an offline-ready MCP bundle, OpenAPI 3.1 spec, and TypeScript SDK."""
    summary = compile_har_to_directory(
        har_path=har_path,
        output_dir=out_dir,
        title=title,
        include_graphql=include_graphql,
    )
    click.echo(json.dumps(summary, indent=2, ensure_ascii=False))


@main.command("diff")
@click.argument("old_har", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("new_har", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def diff_cmd(old_har: Path, new_har: Path) -> None:
    """Compare two HAR captures and report observed API surface differences."""
    old_cap = parse_and_sanitize_har_file(old_har)
    new_cap = parse_and_sanitize_har_file(new_har)
    old_model, _ = build_intermediate_api_model(old_cap)
    new_model, _ = build_intermediate_api_model(new_cap)
    report = diff_intermediate_models(old_model, new_model)
    click.echo(json.dumps(report.model_dump(), indent=2, ensure_ascii=False))


@main.command("serve")
@click.argument("compiled_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--mode",
    type=click.Choice(["cassette", "simulated-state"]),
    default="cassette",
    help="Execution mode (default: cassette)",
)
def serve_cmd(compiled_dir: Path, mode: str) -> None:
    """Start the offline stdio MCP server from a compiled bundle directory."""
    dispatcher = load_dispatcher_from_directory(compiled_dir, mode=mode)
    asyncio.run(run_stdio_mcp_server(dispatcher))


if __name__ == "__main__":
    main()
