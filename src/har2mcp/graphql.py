"""Separately scoped GraphQL operation extractor from sanitized HAR captures.

Kept distinct from REST route inference so GraphQL POST payloads ({query, operationName, variables})
are analyzed with explicit operation semantics rather than collapsed into a single opaque POST /graphql tool.
"""

from __future__ import annotations

import re
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field

from har2mcp.inference import infer_json_schema
from har2mcp.limits import DEFAULT_LIMITS, HarProcessingLimits
from har2mcp.models import SanitizedHarCapture

GQL_OP_RE = re.compile(r"^\s*(query|mutation|subscription)\b(?:\s+([A-Za-z_][A-Za-z0-9_]*))?", re.IGNORECASE)


class GraphQLOperationEvidence(BaseModel):
    """Evidence for one observed GraphQL operation in a HAR capture."""

    model_config = ConfigDict(extra="forbid")

    operation_name: str
    operation_kind: Literal["query", "mutation", "subscription", "unknown"]
    origin: str
    path: str
    variables_schema: dict[str, Any] = Field(default_factory=dict)
    response_data_schema: dict[str, Any] = Field(default_factory=dict)
    evidence_ordinals: list[int] = Field(default_factory=list)


def extract_graphql_operations(
    capture: SanitizedHarCapture,
    limits: HarProcessingLimits = DEFAULT_LIMITS,
) -> list[GraphQLOperationEvidence]:
    """Inspect POST exchanges for GraphQL envelopes without conflating them with REST resources."""
    grouped: dict[tuple[str, str, str, str], list[tuple[int, Any, Any]]] = {}

    for ex in capture.admitted_exchanges:
        if ex.method != "POST" or ex.request_body_status != "json":
            continue
        if not isinstance(ex.request_body, dict):
            continue
        query_text = ex.request_body.get("query")
        op_name_raw = ex.request_body.get("operationName")
        if not isinstance(query_text, str) and not isinstance(op_name_raw, str):
            continue

        kind = "unknown"
        inferred_name = ""
        if isinstance(query_text, str):
            m = GQL_OP_RE.match(query_text)
            if m:
                kind = m.group(1).lower()
                inferred_name = m.group(2) or ""

        op_name = str(op_name_raw or inferred_name or "anonymous_operation").strip()
        variables = ex.request_body.get("variables")
        resp_data = (
            ex.response_body.get("data")
            if isinstance(ex.response_body, dict) and "data" in ex.response_body
            else ex.response_body
        )
        key = (ex.origin, ex.path, kind, op_name)
        grouped.setdefault(key, []).append((ex.ordinal, variables, resp_data))

    results: list[GraphQLOperationEvidence] = []
    for (origin, path, kind, op_name), records in sorted(grouped.items()):
        ordinals = [r[0] for r in records]
        var_samples = [r[1] for r in records if isinstance(r[1], dict)]
        resp_samples = [r[2] for r in records if r[2] is not None]
        results.append(
            GraphQLOperationEvidence(
                operation_name=op_name,
                operation_kind=kind,  # type: ignore[arg-type]
                origin=origin,
                path=path,
                variables_schema=infer_json_schema(var_samples, limits) if var_samples else {},
                response_data_schema=infer_json_schema(resp_samples, limits) if resp_samples else {},
                evidence_ordinals=ordinals,
            )
        )
    return results
