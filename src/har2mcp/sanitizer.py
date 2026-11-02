"""Bounded HAR parser and multi-layer credential/PII sanitizer."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from har2mcp.limits import DEFAULT_LIMITS, HarProcessingLimits
from har2mcp.models import (
    ExcludedEntryRecord,
    RedactionSummary,
    SanitizedExchange,
    SanitizedHarCapture,
)

REDACTED = "[REDACTED]"

SENSITIVE_HEADER_NAMES = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-access-token",
        "x-csrf-token",
        "x-xsrf-token",
        "csrf-token",
        "x-amz-security-token",
        "x-goog-api-key",
        "x-supabase-key",
        "x-hub-signature",
        "x-hub-signature-256",
        "stripe-signature",
    }
)

SENSITIVE_KEY_SUBSTRINGS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "client_secret",
    "authorization",
    "cookie",
    "session_id",
    "sessionid",
    "jwt",
    "bearer",
    "credit_card",
    "card_number",
    "cvv",
    "cvc",
    "ssn",
    "tax_id",
    "passcode",
    "pin_code",
    "otp",
)

SAFE_RESPONSE_HEADERS = frozenset(
    {
        "content-type",
        "cache-control",
        "etag",
        "vary",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-request-id",
        "retry-after",
    }
)

STATIC_ASSET_EXTENSIONS = frozenset(
    {
        ".js",
        ".mjs",
        ".cjs",
        ".css",
        ".map",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".svg",
        ".ico",
        ".avif",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".mp4",
        ".webm",
        ".mp3",
        ".wav",
        ".pdf",
        ".zip",
        ".wasm",
    }
)

TELEMETRY_HOST_SUFFIXES = (
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "segment.io",
    "segment.com",
    "mixpanel.com",
    "amplitude.com",
    "sentry.io",
    "datadoghq.com",
    "hotjar.com",
    "intercom.io",
    "fullstory.com",
    "clarity.ms",
)

SECRET_VALUE_PATTERNS = (
    re.compile(r"^Bearer\s+[A-Za-z0-9._~+/=-]{8,}$", re.IGNORECASE),
    re.compile(r"^Basic\s+[A-Za-z0-9+/=]{8,}$", re.IGNORECASE),
    re.compile(r"^eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$"),
    re.compile(r"^(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{16,}$"),
    re.compile(r"^sk-[A-Za-z0-9_-]{16,}$"),
    re.compile(r"^AIza[0-9A-Za-z_-]{30,}$"),
    re.compile(r"^AKIA[0-9A-Z]{16}$"),
    re.compile(r"^xox[baprs]-[A-Za-z0-9-]{16,}$"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
)



def is_sensitive_key(key: str) -> bool:
    """Return True if a parameter, header, or JSON field name looks credential-bearing."""
    normalized = re.sub(r"[^a-z0-9_]", "_", key.strip().lower())
    if normalized in SENSITIVE_HEADER_NAMES:
        return True
    return any(token in normalized for token in SENSITIVE_KEY_SUBSTRINGS)


def is_secret_string_value(value: str) -> bool:
    """Return True if a string value matches known credential or token patterns."""
    stripped = value.strip()
    if len(stripped) < 12:
        return False
    return any(pattern.search(stripped) is not None for pattern in SECRET_VALUE_PATTERNS)


def _mime_essence(content_type: str) -> str:
    return content_type.split(";", 1)[0].strip().lower()


def _is_json_mime(essence: str) -> bool:
    return essence in ("application/json", "text/json") or essence.endswith("+json")


def _bounded_json(text: str, max_depth: int) -> Any:
    """Bound nesting before the standard JSON parser allocates nested containers."""
    depth, quoted, escaped = 0, False, False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > max_depth:
                raise ValueError("JSON exceeds the configured nesting limit")
        elif character in "]}":
            depth -= 1
    return json.loads(text)


def _sanitize_json_value(
    value: Any,
    limits: HarProcessingLimits,
    summary: RedactionSummary,
    depth: int = 0,
) -> Any:
    """Recursively sanitize a parsed JSON value while enforcing depth and property bounds."""
    if depth > limits.max_json_depth:
        return "[TRUNCATED_MAX_DEPTH]"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for idx, (k, v) in enumerate(value.items()):
            if idx >= limits.max_schema_properties:
                result["__truncated_properties__"] = True
                break
            key_str = str(k)
            if is_sensitive_key(key_str):
                summary.redacted_body_fields += 1
                result[key_str] = REDACTED
            else:
                result[key_str] = _sanitize_json_value(v, limits, summary, depth + 1)
        return result
    if isinstance(value, list):
        sampled = value[: limits.max_array_items_sampled]
        return [_sanitize_json_value(item, limits, summary, depth + 1) for item in sampled]
    if isinstance(value, str):
        if is_secret_string_value(value):
            summary.redacted_body_fields += 1
            return REDACTED
        if len(value) > limits.max_header_value_length:
            return value[: limits.max_header_value_length] + "...[TRUNCATED]"
        return value
    return value


def _detect_auth_scheme(
    header_name_lower: str,
    raw_value: str,
    summary: RedactionSummary,
) -> None:
    """Record the type of authentication observed without storing the secret value."""
    scheme: str | None = None
    env_var: str | None = None
    env_desc: str | None = None

    if header_name_lower == "authorization":
        val_stripped = raw_value.strip()
        if val_stripped.lower().startswith("bearer "):
            scheme = "bearer"
            env_var = "HAR2MCP_BEARER_TOKEN"
            env_desc = "Bearer token for Authorization header"
        elif val_stripped.lower().startswith("basic "):
            scheme = "basic"
            env_var = "HAR2MCP_BASIC_AUTH"
            env_desc = "Base64 credentials for Basic Authorization header"
        else:
            scheme = "authorization_header"
            env_var = "HAR2MCP_AUTH_HEADER"
            env_desc = "Raw Authorization header value"
    elif header_name_lower in ("cookie", "set-cookie"):
        scheme = "cookie"
        env_var = "HAR2MCP_COOKIE"
        env_desc = "Session cookie header value"
    elif "csrf" in header_name_lower or "xsrf" in header_name_lower:
        scheme = "csrf_header"
        env_var = "HAR2MCP_CSRF_TOKEN"
        env_desc = f"CSRF token for {header_name_lower} header"
    elif "key" in header_name_lower or "token" in header_name_lower:
        scheme = "api_key_header"
        safe_suffix = re.sub(r"[^A-Z0-9]+", "_", header_name_lower.upper()).strip("_")
        env_var = f"HAR2MCP_{safe_suffix}"
        env_desc = f"API key/token for {header_name_lower} header"

    if scheme and scheme not in summary.detected_auth_schemes:
        summary.detected_auth_schemes.append(scheme)
    if env_var and env_desc and env_var not in summary.required_env_vars:
        summary.required_env_vars[env_var] = env_desc



def _sanitize_request_body(
    post_data: Any,
    limits: HarProcessingLimits,
    summary: RedactionSummary,
) -> tuple[str, str, Any]:
    """Return (content_type_essence, body_status, sanitized_payload) for a HAR request."""
    if not isinstance(post_data, dict):
        return ("", "none", None)

    mime_type = str(post_data.get("mimeType") or "")
    essence = _mime_essence(mime_type)
    raw_text = post_data.get("text")
    params = post_data.get("params")

    if raw_text is None and not params:
        return (essence, "none", None)

    text_str = str(raw_text or "")
    if len(text_str.encode("utf-8", errors="replace")) > limits.max_body_bytes:
        summary.withheld_bodies += 1
        return (essence, "withheld_oversized", None)

    if essence.startswith("multipart/"):
        summary.withheld_bodies += 1
        summary.redacted_body_fields += 1
        return (essence, "withheld_multipart", None)

    if essence == "application/x-www-form-urlencoded":
        pairs: list[tuple[str, str]] = []
        if isinstance(params, list) and params:
            for item in params[: limits.max_query_params]:
                if isinstance(item, dict):
                    k = str(item.get("name") or "")
                    v = str(item.get("value") or "")
                    pairs.append((k, v))
        elif text_str:
            pairs = parse_qsl(text_str, keep_blank_values=True)[: limits.max_query_params]

        sanitized_form: dict[str, Any] = {}
        for k, v in pairs:
            if is_sensitive_key(k) or is_secret_string_value(v):
                summary.redacted_body_fields += 1
                sanitized_form[k] = REDACTED
            else:
                sanitized_form[k] = v[: limits.max_header_value_length]
        return (essence, "form_urlencoded", sanitized_form)

    if _is_json_mime(essence) or (not essence and text_str.lstrip().startswith(("{", "["))):
        try:
            parsed = _bounded_json(text_str, limits.max_json_depth)
        except (ValueError, RecursionError):
            summary.withheld_bodies += 1
            return (essence or "application/json", "withheld_malformed_json", None)
        sanitized = _sanitize_json_value(parsed, limits, summary, depth=0)
        return (essence or "application/json", "json", sanitized)

    summary.withheld_bodies += 1
    return (essence, "withheld_unsupported_mime", None)


def _sanitize_response_body(
    content_obj: Any,
    limits: HarProcessingLimits,
    summary: RedactionSummary,
) -> tuple[str, str, Any]:
    """Return (content_type_essence, body_status, sanitized_payload) for a HAR response."""
    if not isinstance(content_obj, dict):
        return ("", "none", None)

    mime_type = str(content_obj.get("mimeType") or "")
    essence = _mime_essence(mime_type)
    encoding = str(content_obj.get("encoding") or "").strip().lower()
    raw_text = content_obj.get("text")

    if raw_text is None or raw_text == "":
        return (essence, "none", None)

    if encoding == "base64":
        summary.withheld_bodies += 1
        return (essence, "withheld_binary_or_base64", None)

    text_str = str(raw_text)
    if len(text_str.encode("utf-8", errors="replace")) > limits.max_body_bytes:
        summary.withheld_bodies += 1
        return (essence, "withheld_oversized", None)

    if essence in (
        "text/html",
        "application/xhtml+xml",
        "application/javascript",
        "text/javascript",
        "application/ecmascript",
    ):
        summary.withheld_bodies += 1
        return (essence, "withheld_html_or_script", None)

    if _is_json_mime(essence) or (
        essence in ("text/plain", "") and text_str.lstrip().startswith(("{", "["))
    ):
        try:
            parsed = _bounded_json(text_str, limits.max_json_depth)
        except (ValueError, RecursionError):
            summary.withheld_bodies += 1
            return (essence or "application/json", "withheld_malformed_json", None)
        sanitized = _sanitize_json_value(parsed, limits, summary, depth=0)
        return (essence or "application/json", "json", sanitized)

    if essence == "text/plain":
        if is_secret_string_value(text_str):
            summary.redacted_body_fields += 1
            return (essence, "text_safe", REDACTED)
        if "<script" in text_str.lower() or "<!doctype html" in text_str.lower():
            summary.withheld_bodies += 1
            return (essence, "withheld_html_or_script", None)
        return (essence, "text_safe", text_str[: limits.max_header_value_length])

    summary.withheld_bodies += 1
    return (essence, "withheld_unsupported_mime", None)


def parse_and_sanitize_har_file(
    har_path: str | Path,
    limits: HarProcessingLimits = DEFAULT_LIMITS,
    include_telemetry: bool = False,
) -> SanitizedHarCapture:
    """Load, bound-check, and sanitize a HAR file from disk without executing any content."""
    resolved = Path(har_path).resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"HAR file not found: {resolved}")

    file_size = resolved.stat().st_size
    if file_size > limits.max_har_file_bytes:
        raise ValueError(
            f"HAR file size ({file_size} bytes) exceeds limit ({limits.max_har_file_bytes} bytes)"
        )

    with resolved.open("rb") as stream:
        raw_bytes = stream.read(limits.max_har_file_bytes + 1)
    if len(raw_bytes) > limits.max_har_file_bytes:
        raise ValueError("HAR grew beyond the configured byte limit while reading")
    try:
        raw_doc = _bounded_json(raw_bytes.decode("utf-8-sig"), limits.max_json_depth + 8)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"Invalid UTF-8 JSON in HAR file: {exc}") from exc

    return parse_and_sanitize_har_dict(
        raw_doc,
        source_filename=resolved.name,
        limits=limits,
        include_telemetry=include_telemetry,
    )


def parse_and_sanitize_har_dict(
    raw_doc: Any,
    source_filename: str = "memory.har",
    limits: HarProcessingLimits = DEFAULT_LIMITS,
    include_telemetry: bool = False,
) -> SanitizedHarCapture:
    """Validate and sanitize an in-memory HAR dictionary."""
    if not isinstance(raw_doc, dict) or not isinstance(raw_doc.get("log"), dict):
        raise ValueError("HAR root must contain a 'log' object")

    entries = raw_doc["log"].get("entries")
    if not isinstance(entries, list):
        raise ValueError("HAR 'log.entries' must be a list")

    if len(entries) > limits.max_entries:
        raise ValueError(
            f"HAR entry count ({len(entries)}) exceeds limit ({limits.max_entries})"
        )

    summary = RedactionSummary()
    admitted: list[SanitizedExchange] = []
    excluded: list[ExcludedEntryRecord] = []

    for ordinal, entry in enumerate(entries):
        if not isinstance(entry, dict):
            excluded.append(ExcludedEntryRecord(ordinal=ordinal, reason="invalid_entry"))
            continue

        req = entry.get("request")
        resp = entry.get("response")
        if not isinstance(req, dict) or not isinstance(resp, dict):
            excluded.append(ExcludedEntryRecord(ordinal=ordinal, reason="invalid_entry"))
            continue

        raw_method = str(req.get("method") or "").strip().upper()
        raw_url = str(req.get("url") or "").strip()
        if raw_method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"}:
            excluded.append(ExcludedEntryRecord(ordinal=ordinal, reason="invalid_entry"))
            continue
        if not raw_method or not raw_url:
            excluded.append(ExcludedEntryRecord(ordinal=ordinal, reason="invalid_entry"))
            continue

        if len(raw_url) > limits.max_url_length:
            excluded.append(
                ExcludedEntryRecord(
                    ordinal=ordinal,
                    reason="url_too_long",
                    method=raw_method,
                    url_preview="[WITHHELD_URL_TOO_LONG]",
                )
            )
            continue

        try:
            split = urlsplit(raw_url)
        except ValueError:
            excluded.append(
                ExcludedEntryRecord(ordinal=ordinal, reason="invalid_entry", method=raw_method)
            )
            continue

        scheme = split.scheme.lower()
        if scheme not in ("http", "https") or not split.hostname:
            excluded.append(
                ExcludedEntryRecord(
                    ordinal=ordinal,
                    reason="unsupported_scheme",
                    method=raw_method,
                    url_preview=f"{scheme}://...",
                )
            )
            continue

        if split.username is not None or split.password is not None:
            summary.redacted_url_userinfo += 1

        host_lower = split.hostname.lower()
        try:
            port = split.port
        except ValueError:
            excluded.append(
                ExcludedEntryRecord(ordinal=ordinal, reason="invalid_entry", method=raw_method)
            )
            continue

        default_port = 80 if scheme == "http" else 443
        origin = (
            f"{scheme}://{host_lower}"
            if (port is None or port == default_port)
            else f"{scheme}://{host_lower}:{port}"
        )
        path = split.path or "/"

        if raw_method == "OPTIONS":
            excluded.append(
                ExcludedEntryRecord(
                    ordinal=ordinal,
                    reason="cors_preflight",
                    method=raw_method,
                    url_preview=f"{origin}{path}",
                )
            )
            continue

        if not include_telemetry and any(
            host_lower == suffix or host_lower.endswith("." + suffix)
            for suffix in TELEMETRY_HOST_SUFFIXES
        ):
            excluded.append(
                ExcludedEntryRecord(
                    ordinal=ordinal,
                    reason="telemetry_domain",
                    method=raw_method,
                    url_preview=f"{origin}{path}",
                )
            )
            continue

        path_lower = path.lower()
        if any(path_lower.endswith(ext) for ext in STATIC_ASSET_EXTENSIONS):
            excluded.append(
                ExcludedEntryRecord(
                    ordinal=ordinal,
                    reason="static_asset",
                    method=raw_method,
                    url_preview=f"{origin}{path}",
                )
            )
            continue

        req_cookies = req.get("cookies")
        if isinstance(req_cookies, list) and req_cookies:
            summary.redacted_cookies += len(req_cookies)
        resp_cookies = resp.get("cookies")
        if isinstance(resp_cookies, list) and resp_cookies:
            summary.redacted_cookies += len(resp_cookies)

        req_headers_clean: dict[str, str] = {}
        raw_req_headers = req.get("headers")
        if isinstance(raw_req_headers, list):
            for h in raw_req_headers[: limits.max_headers_per_message]:
                if not isinstance(h, dict):
                    continue
                h_name = str(h.get("name") or "").strip()[: limits.max_header_name_length]
                h_val = str(h.get("value") or "").strip()
                if not h_name or h_name.startswith(":"):
                    continue
                h_lower = h_name.lower()
                if is_sensitive_key(h_lower) or is_secret_string_value(h_val):
                    summary.redacted_headers += 1
                    if h_lower in ("cookie", "set-cookie"):
                        summary.redacted_cookies += 1
                    _detect_auth_scheme(h_lower, h_val, summary)
                    req_headers_clean[h_lower] = REDACTED
                elif h_lower in ("accept", "content-type"):
                    req_headers_clean[h_lower] = h_val[: limits.max_header_value_length]

        query_clean: dict[str, list[str]] = {}
        raw_query_pairs = parse_qsl(split.query, keep_blank_values=True)[
            : limits.max_query_params
        ]
        for q_key, q_val in raw_query_pairs:
            q_key_clean = q_key.strip()[: limits.max_header_name_length]
            if not q_key_clean:
                continue
            if is_sensitive_key(q_key_clean) or is_secret_string_value(q_val):
                summary.redacted_query_params += 1
                if "api_key_query" not in summary.detected_auth_schemes:
                    summary.detected_auth_schemes.append("api_key_query")
                env_name = "HAR2MCP_QUERY_" + re.sub(
                    r"[^A-Z0-9]+", "_", q_key_clean.upper()
                ).strip("_")
                summary.required_env_vars.setdefault(
                    env_name, f"Secret query parameter '{q_key_clean}'"
                )
                query_clean.setdefault(q_key_clean, []).append(REDACTED)
            else:
                query_clean.setdefault(q_key_clean, []).append(
                    q_val[: limits.max_header_value_length]
                )

        req_mime, req_body_status, req_body = _sanitize_request_body(
            req.get("postData"), limits, summary
        )

        raw_status = resp.get("status")
        status_code = raw_status if type(raw_status) is int and 100 <= raw_status <= 599 else 0

        resp_headers_clean: dict[str, str] = {}
        raw_resp_headers = resp.get("headers")
        if isinstance(raw_resp_headers, list):
            for h in raw_resp_headers[: limits.max_headers_per_message]:
                if not isinstance(h, dict):
                    continue
                h_name = str(h.get("name") or "").strip()[: limits.max_header_name_length]
                h_val = str(h.get("value") or "").strip()
                if not h_name:
                    continue
                h_lower = h_name.lower()
                if is_sensitive_key(h_lower) or is_secret_string_value(h_val):
                    summary.redacted_headers += 1
                    if h_lower in ("cookie", "set-cookie"):
                        summary.redacted_cookies += 1
                    _detect_auth_scheme(h_lower, h_val, summary)
                elif h_lower in SAFE_RESPONSE_HEADERS:
                    resp_headers_clean[h_lower] = h_val[: limits.max_header_value_length]

        resp_mime, resp_body_status, resp_body = _sanitize_response_body(
            resp.get("content"), limits, summary
        )

        if (
            raw_method == "GET"
            and resp_body_status == "withheld_html_or_script"
            and req_body_status == "none"
        ):
            excluded.append(
                ExcludedEntryRecord(
                    ordinal=ordinal,
                    reason="non_api_html_or_script",
                    method=raw_method,
                    url_preview=f"{origin}{path}",
                )
            )
            continue

        admitted.append(
            SanitizedExchange(
                ordinal=ordinal,
                method=raw_method,
                origin=origin,
                path=path,
                query_params=query_clean,
                request_headers=req_headers_clean,
                request_content_type=req_mime,
                request_body_status=req_body_status,  # type: ignore[arg-type]
                request_body=req_body,
                status=status_code,
                response_headers=resp_headers_clean,
                response_content_type=resp_mime,
                response_body_status=resp_body_status,  # type: ignore[arg-type]
                response_body=resp_body,
            )
        )

    return SanitizedHarCapture(
        source_filename=source_filename,
        total_raw_entries=len(entries),
        admitted_exchanges=admitted,
        excluded_entries=excluded,
        redaction_summary=summary,
    )

