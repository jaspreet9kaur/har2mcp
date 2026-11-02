"""Pydantic data models for har2mcp sanitization, intermediate API evidence, and cassettes."""

from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field


class RedactionSummary(BaseModel):
    """Summary of credentials and sensitive fields scrubbed during HAR sanitization."""

    model_config = ConfigDict(extra="forbid")

    redacted_headers: int = 0
    redacted_cookies: int = 0
    redacted_url_userinfo: int = 0
    redacted_query_params: int = 0
    redacted_body_fields: int = 0
    withheld_bodies: int = 0
    detected_auth_schemes: list[str] = Field(default_factory=list)
    required_env_vars: dict[str, str] = Field(default_factory=dict)
    limitations_notice: str = (
        "Heuristic header, key-name, and token-pattern sanitization scrubs common credentials "
        "(Authorization, Cookie, API keys, JWTs, URL userinfo, form/JSON secrets) and withholds "
        "binary/multipart/HTML-script payloads, but cannot guarantee detection of every custom or "
        "domain-specific secret. Review cassette.json before sharing."
    )


class ExcludedEntryRecord(BaseModel):
    """Audit record for a HAR entry excluded from API surface projection."""

    model_config = ConfigDict(extra="forbid")

    ordinal: int
    reason: Literal[
        "invalid_entry",
        "unsupported_scheme",
        "url_too_long",
        "cors_preflight",
        "static_asset",
        "telemetry_domain",
        "non_api_html_or_script",
    ]
    method: str = ""
    url_preview: str = ""


class SanitizedExchange(BaseModel):
    """One sanitized HTTP request/response exchange admitted from a HAR capture."""

    model_config = ConfigDict(extra="forbid")

    ordinal: int
    method: str
    origin: str
    path: str
    query_params: dict[str, list[str]] = Field(default_factory=dict)
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_content_type: str = ""
    request_body_status: Literal[
        "none",
        "json",
        "form_urlencoded",
        "withheld_multipart",
        "withheld_binary_or_base64",
        "withheld_unsupported_mime",
        "withheld_oversized",
        "withheld_malformed_json",
    ] = "none"
    request_body: Any = None
    status: int
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_content_type: str = ""
    response_body_status: Literal[
        "none",
        "json",
        "text_safe",
        "withheld_binary_or_base64",
        "withheld_html_or_script",
        "withheld_unsupported_mime",
        "withheld_oversized",
        "withheld_malformed_json",
    ] = "none"
    response_body: Any = None


class SanitizedHarCapture(BaseModel):
    """Complete result of bounded HAR parsing and sanitization."""

    model_config = ConfigDict(extra="forbid")

    source_filename: str
    total_raw_entries: int
    admitted_exchanges: list[SanitizedExchange]
    excluded_entries: list[ExcludedEntryRecord]
    redaction_summary: RedactionSummary


class RouteSegmentEvidence(BaseModel):
    """Evidence and confidence for a single segment of an inferred route template."""

    model_config = ConfigDict(extra="forbid")

    segment_index: int
    kind: Literal["literal", "parameter"]
    name: str
    parameter_rule: Literal[
        "none",
        "uuid",
        "hex_digest",
        "iso_date",
        "numeric_multi_sample",
        "numeric_single_sample",
        "slug_multi_sample",
    ] = "none"
    confidence: Literal[
        "exact_literal",
        "high_format_match",
        "verified_multi_sample",
        "inferred_single_sample",
    ] = "exact_literal"
    observed_values: list[str] = Field(default_factory=list)


class QueryParameterEvidence(BaseModel):
    """Observed query parameter metadata across an endpoint group."""

    model_config = ConfigDict(extra="forbid")

    name: str
    inferred_schema: dict[str, Any]
    observed_in_all_requests: bool
    sample_count: int


class EndpointToolModel(BaseModel):
    """Evidence-backed model for one grouped API endpoint / MCP tool."""

    model_config = ConfigDict(extra="forbid")

    tool_name: str
    method: str
    origin: str
    path_template: str
    route_confidence: Literal[
        "exact_literal",
        "high_format_match",
        "verified_multi_sample",
        "inferred_single_sample",
    ]
    segments: list[RouteSegmentEvidence]
    observed_path_variants: list[str]
    path_parameters: list[str]
    query_parameters: list[QueryParameterEvidence]
    request_content_types: list[str]
    request_body_schema: dict[str, Any] | None = None
    response_statuses: list[int]
    response_content_types: list[str]
    response_schemas_by_status: dict[str, dict[str, Any]] = Field(default_factory=dict)
    evidence_ordinals: list[int]
    is_state_changing: bool
    uncertainty_notes: list[str] = Field(default_factory=list)


class IntermediateApiModel(BaseModel):
    """Complete evidence-based intermediate API model derived from a sanitized HAR."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0.0"
    source_filename: str
    primary_origin: str
    all_origins: list[str]
    endpoints: list[EndpointToolModel]
    redaction_summary: RedactionSummary
    epistemic_limits: list[str] = Field(
        default_factory=lambda: [
            "Observed HAR traffic is a finite runtime sample and cannot establish a complete server specification.",
            "Path parameters with confidence 'inferred_single_sample' were generalized from a single observed numeric/identifier segment; check observed_path_variants.",
            "Query parameters and JSON body properties observed in every sample are still marked optional or sample-derived because server-side validation rules are not directly observable from network captures.",
            "Recorded GET exchanges do not establish server-side create, update, delete, or authorization semantics.",
        ]
    )


class CassetteEntry(BaseModel):
    """One deterministic offline replay entry stored in cassette.json."""

    model_config = ConfigDict(extra="forbid")

    ordinal: int
    tool_name: str
    method: str
    origin: str
    path: str
    path_template: str
    query_params: dict[str, list[str]] = Field(default_factory=dict)
    request_body: Any = None
    status: int
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_content_type: str = ""
    response_body: Any = None


class OfflineCassette(BaseModel):
    """Sanitized deterministic offline replay cassette."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0.0"
    source_filename: str
    authority: Literal["recorded-cassette"] = "recorded-cassette"
    entries: list[CassetteEntry]

