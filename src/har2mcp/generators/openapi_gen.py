"""OpenAPI 3.1.0 specification generator from an IntermediateApiModel."""

from __future__ import annotations

from typing import Any

from har2mcp.models import EndpointToolModel, IntermediateApiModel


def build_tool_input_schema(ep: EndpointToolModel) -> dict[str, Any]:
    """Construct the JSON Schema for an MCP tool's input arguments."""
    properties: dict[str, Any] = {}
    required: list[str] = []

    for seg in ep.segments:
        if seg.kind == "parameter":
            prop_type = "integer" if seg.parameter_rule.startswith("numeric") else "string"
            properties[seg.name] = {
                "type": prop_type,
                "description": (
                    f"Path parameter '{seg.name}' (confidence: {seg.confidence}, "
                    f"rule: {seg.parameter_rule})."
                ),
            }
            required.append(seg.name)

    for q in ep.query_parameters:
        if q.name not in properties:
            properties[q.name] = {
                **q.inferred_schema,
                "description": (
                    f"Query parameter '{q.name}' (observed in {q.sample_count} sample(s); "
                    "marked optional because HAR samples cannot establish server requiredness)."
                ),
            }

    if ep.request_body_schema is not None:
        properties["body"] = {
            **ep.request_body_schema,
            "description": "JSON or form request body payload inferred from HAR samples.",
        }

    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        schema["required"] = required
    return schema


def generate_openapi_31_spec(
    model: IntermediateApiModel,
    title: str = "HAR-Inferred API Surface",
    version: str = "0.1.0",
) -> dict[str, Any]:
    """Compile an IntermediateApiModel into a valid OpenAPI 3.1.0 document."""
    servers = (
        [{"url": origin} for origin in model.all_origins]
        if model.all_origins
        else [{"url": "https://example.invalid"}]
    )

    paths: dict[str, dict[str, Any]] = {}
    for ep in model.endpoints:
        path_item = paths.setdefault(ep.path_template, {})
        method_lower = ep.method.lower()
        if method_lower in path_item:
            raise ValueError("Multiple origins share the same method/path; compile separate captures per origin")

        parameters: list[dict[str, Any]] = []
        for seg in ep.segments:
            if seg.kind == "parameter":
                p_type = "integer" if seg.parameter_rule.startswith("numeric") else "string"
                parameters.append(
                    {
                        "name": seg.name,
                        "in": "path",
                        "required": True,
                        "schema": {"type": p_type},
                        "description": f"Inferred via {seg.parameter_rule} ({seg.confidence})",
                    }
                )

        for q in ep.query_parameters:
            parameters.append(
                {
                    "name": q.name,
                    "in": "query",
                    "required": False,
                    "schema": q.inferred_schema,
                    "description": f"Observed in {q.sample_count} request(s).",
                }
            )

        responses: dict[str, Any] = {}
        for st in ep.response_statuses:
            st_key = str(st) if st > 0 else "default"
            st_schema = ep.response_schemas_by_status.get(str(st))
            resp_entry: dict[str, Any] = {
                "description": f"Observed HTTP {st} response in HAR capture",
            }
            if st_schema is not None:
                mime = (
                    ep.response_content_types[0]
                    if ep.response_content_types
                    else "application/json"
                )
                resp_entry["content"] = {mime: {"schema": st_schema}}
            responses[st_key] = resp_entry

        if not responses:
            responses["200"] = {"description": "Observed exchange with no response status"}

        operation: dict[str, Any] = {
            "servers": [{"url": ep.origin}],
            "operationId": ep.tool_name,
            "summary": f"{ep.method} {ep.path_template} ({ep.origin})",
            "description": (
                f"Inferred from HAR evidence ordinals {ep.evidence_ordinals}. "
                f"Route confidence: {ep.route_confidence}. "
                f"Observed path variants: {ep.observed_path_variants}."
            ),
            "parameters": parameters,
            "responses": responses,
            "x-har2mcp-evidence": {
                "origin": ep.origin,
                "route_confidence": ep.route_confidence,
                "observed_path_variants": ep.observed_path_variants,
                "evidence_ordinals": ep.evidence_ordinals,
                "uncertainty_notes": ep.uncertainty_notes,
            },
        }

        if ep.request_body_schema is not None:
            req_mime = (
                ep.request_content_types[0]
                if ep.request_content_types
                else "application/json"
            )
            operation["requestBody"] = {
                "required": False,
                "content": {
                    req_mime: {
                        "schema": ep.request_body_schema,
                    }
                },
            }

        path_item[method_lower] = operation

    security_schemes: dict[str, Any] = {}
    for scheme in model.redaction_summary.detected_auth_schemes:
        if scheme == "bearer":
            security_schemes["bearerAuth"] = {"type": "http", "scheme": "bearer"}
        elif scheme == "basic":
            security_schemes["basicAuth"] = {"type": "http", "scheme": "basic"}
        elif scheme == "api_key_header":
            security_schemes["apiKeyHeader"] = {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key",
            }
        elif scheme == "cookie":
            security_schemes["cookieAuth"] = {
                "type": "apiKey",
                "in": "cookie",
                "name": "session",
            }

    spec: dict[str, Any] = {
        "openapi": "3.1.0",
        "jsonSchemaDialect": "https://spec.openapis.org/oas/3.1/dialect/base",
        "info": {
            "title": title,
            "version": version,
            "description": (
                f"Evidence-based OpenAPI 3.1.0 specification compiled from '{model.source_filename}'. "
                "NOTE: Derived from runtime network observations; does not establish a complete server contract."
            ),
        },
        "servers": servers,
        "paths": paths,
        "x-har2mcp-epistemic-limits": model.epistemic_limits,
        "x-har2mcp-redaction-summary": model.redaction_summary.model_dump(),
    }
    if security_schemes:
        spec["components"] = {"securitySchemes": security_schemes}
    return spec
