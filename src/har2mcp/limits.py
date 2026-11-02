"""Bounded parsing, memory, and network resource limits for har2mcp."""

from dataclasses import dataclass


@dataclass(frozen=True)
class HarProcessingLimits:
    """Explicit bounds enforced during HAR admission, sanitization, and schema inference."""

    max_har_file_bytes: int = 50 * 1024 * 1024  # 50 MiB
    max_entries: int = 5_000
    max_url_length: int = 4_096
    max_headers_per_message: int = 128
    max_header_name_length: int = 256
    max_header_value_length: int = 8_192
    max_query_params: int = 128
    max_body_bytes: int = 2 * 1024 * 1024  # 2 MiB per request/response body
    max_json_depth: int = 24
    max_schema_properties: int = 256
    max_array_items_sampled: int = 64
    max_route_segments: int = 32
    max_tool_name_length: int = 60
    default_live_timeout_seconds: float = 15.0
    max_live_response_bytes: int = 2 * 1024 * 1024  # 2 MiB


DEFAULT_LIMITS = HarProcessingLimits()
