"""Deterministic offline cassette replay engine (default safe mode)."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from har2mcp.models import CassetteEntry, EndpointToolModel, OfflineCassette


def render_path_template(path_template: str, path_args: dict[str, Any]) -> str:
    """Substitute path parameters safely using URL-segment encoding, refusing traversal."""

    def _replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in path_args or path_args[name] is None:
            raise ValueError(f"Missing required path parameter: '{name}'")
        val_str = str(path_args[name]).strip()
        if not val_str or "/" in val_str or "\\" in val_str or val_str in (".", ".."):
            raise ValueError(f"Invalid path parameter value for '{name}': {val_str!r}")
        return quote(val_str, safe="-._~")

    return re.sub(r"\{([a-zA-Z0-9_]+)\}", _replace, path_template)


def _normalize_query_map(query_args: dict[str, Any] | None) -> dict[str, list[str]]:
    if not query_args:
        return {}
    normalized: dict[str, list[str]] = {}
    for k, v in sorted(query_args.items()):
        if v is None:
            continue
        if isinstance(v, list):
            normalized[str(k)] = [str(item) for item in v]
        elif isinstance(v, bool):
            normalized[str(k)] = ["true" if v else "false"]
        else:
            normalized[str(k)] = [str(v)]
    return normalized


class CassetteReplayEngine:
    """Replays sanitized HAR exchanges deterministically offline without network access."""

    def __init__(self, cassette: OfflineCassette) -> None:
        self._cassette = cassette

    def replay_tool_call(
        self,
        endpoint: EndpointToolModel,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        args = arguments or {}
        path_args = {p: args.get(p) for p in endpoint.path_parameters}
        rendered_path = render_path_template(endpoint.path_template, path_args)

        query_names = {q.name for q in endpoint.query_parameters}
        query_args = {k: v for k, v in args.items() if k in query_names and v is not None}
        norm_query = _normalize_query_map(query_args)

        candidates = [
            e
            for e in self._cassette.entries
            if (e.tool_name == endpoint.tool_name and e.origin == endpoint.origin
                and e.method == endpoint.method and e.path_template == endpoint.path_template)
        ]

        # Tier 1: Exact path and exact query parameters match
        for entry in candidates:
            if (entry.path == rendered_path and entry.query_params == norm_query
                    and entry.request_body == args.get("body")):
                return self._format_hit(entry, match_tier="exact_path_and_query")

        return {
            "authority": "recorded-cassette",
            "matched": False,
            "status": 404,
            "error": f"No recorded cassette exchange found for {endpoint.method} {rendered_path}",
        }

    @staticmethod
    def _format_hit(
        entry: CassetteEntry,
        match_tier: str,
        Requested_path: str | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "authority": "recorded-cassette",
            "matched": True,
            "match_tier": match_tier,
            "matched_ordinal": entry.ordinal,
            "method": entry.method,
            "origin": entry.origin,
            "recorded_path": entry.path,
            "status": entry.status,
            "content_type": entry.response_content_type,
            "body": entry.response_body,
        }
        if Requested_path and Requested_path != entry.path:
            result["requested_path"] = Requested_path
            result["note"] = (
                "Exact path was not present in the recorded HAR; returned earliest recorded "
                f"sample (ordinal {entry.ordinal}) for template {entry.path_template}."
            )
        return result
