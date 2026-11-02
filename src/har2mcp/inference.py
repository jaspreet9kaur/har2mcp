"""Evidence-based route parameterization and JSON Schema inference engine."""

from __future__ import annotations

from collections import Counter
import re
from typing import Any

from har2mcp.limits import DEFAULT_LIMITS, HarProcessingLimits
from har2mcp.models import (
    CassetteEntry,
    EndpointToolModel,
    IntermediateApiModel,
    OfflineCassette,
    QueryParameterEvidence,
    RouteSegmentEvidence,
    SanitizedExchange,
    SanitizedHarCapture,
)

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
HEX_DIGEST_RE = re.compile(r"^[0-9a-f]{24,}$", re.IGNORECASE)
ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
NUMERIC_RE = re.compile(r"^\d+$")
VERSION_TOKEN_RE = re.compile(r"^v\d+(?:\.\d+)?$", re.IGNORECASE)

DROPPED_TOOL_TOKENS = frozenset({"api", "apis", "rest", "public", "internal"})
STOP_LITERAL_WORDS = frozenset(
    {
        "api",
        "apis",
        "v1",
        "v2",
        "v3",
        "v4",
        "auth",
        "login",
        "logout",
        "me",
        "self",
        "current",
        "health",
        "status",
        "metrics",
        "search",
        "export",
        "import",
        "settings",
        "config",
        "graphql",
        "count",
        "summary",
        "batch",
    }
)


def _singularize(word: str) -> str:
    clean = re.sub(r"[^a-z0-9_]", "_", word.lower()).strip("_")
    if clean.endswith("ies") and len(clean) > 3:
        return clean[:-3] + "y"
    if clean.endswith("ses") and len(clean) > 4:
        return clean[:-2]
    if clean.endswith("s") and not clean.endswith("ss") and len(clean) > 2:
        return clean[:-1]
    return clean or "item"


def _sanitize_identifier(text: str) -> str:
    cleaned = re.sub(r"[^a-z0-9_]+", "_", text.lower())
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    return cleaned or "endpoint"


def infer_json_schema(
    samples: list[Any],
    limits: HarProcessingLimits = DEFAULT_LIMITS,
    depth: int = 0,
) -> dict[str, Any]:
    """Infer a Draft 2020-12 / OpenAPI 3.1 compatible JSON Schema from observed samples."""
    if not samples or depth > limits.max_json_depth:
        return {}

    non_null = [s for s in samples if s is not None]
    has_null = len(non_null) < len(samples)

    if not non_null:
        return {"type": "null"}

    kind_set: set[str] = set()
    for val in non_null:
        if isinstance(val, bool):
            kind_set.add("boolean")
        elif isinstance(val, int):
            kind_set.add("integer")
        elif isinstance(val, float):
            kind_set.add("number")
        elif isinstance(val, str):
            kind_set.add("string")
        elif isinstance(val, list):
            kind_set.add("array")
        elif isinstance(val, dict):
            kind_set.add("object")

    if "integer" in kind_set and "number" in kind_set:
        kind_set.remove("integer")

    if len(kind_set) == 1:
        only_kind = next(iter(kind_set))
        base_schema: dict[str, Any]
        if only_kind == "object":
            dict_samples = [s for s in non_null if isinstance(s, dict)]
            all_keys: list[str] = []
            seen_keys: set[str] = set()
            for d in dict_samples:
                for k in d.keys():
                    ks = str(k)
                    if ks not in seen_keys and len(all_keys) < limits.max_schema_properties:
                        seen_keys.add(ks)
                        all_keys.append(ks)
            props: dict[str, Any] = {}
            for k in all_keys:
                key_vals = [d[k] for d in dict_samples if k in d]
                props[k] = infer_json_schema(key_vals, limits, depth + 1)
            base_schema = {
                "type": "object",
                "properties": props,
            }
        elif only_kind == "array":
            list_samples = [s for s in non_null if isinstance(s, list)]
            flat_items: list[Any] = []
            for lst in list_samples:
                for item in lst[: limits.max_array_items_sampled]:
                    flat_items.append(item)
                    if len(flat_items) >= limits.max_array_items_sampled:
                        break
            item_schema = infer_json_schema(flat_items, limits, depth + 1) if flat_items else {}
            base_schema = {
                "type": "array",
                "items": item_schema,
            }
        else:
            base_schema = {"type": only_kind}

        if has_null:
            t = base_schema.get("type")
            if isinstance(t, str):
                base_schema = {**base_schema, "type": [t, "null"]}
        return base_schema

    sorted_types = sorted(kind_set)
    if has_null:
        sorted_types.append("null")
    return {"type": sorted_types}


def _classify_segment_format(seg: str) -> str | None:
    """Return high-confidence format rule for a single URL path segment, if any."""
    if not seg or VERSION_TOKEN_RE.match(seg) or seg.lower() in STOP_LITERAL_WORDS:
        return None
    if UUID_RE.match(seg):
        return "uuid"
    if HEX_DIGEST_RE.match(seg):
        return "hex_digest"
    if ISO_DATE_RE.match(seg):
        return "iso_date"
    if NUMERIC_RE.match(seg):
        return "numeric"
    return None


def _param_name_for_position(
    segments: list[str],
    idx: int,
    rule: str,
    used_names: set[str],
) -> str:
    prev = segments[idx - 1] if idx > 0 else ""
    stem = _singularize(prev) if prev and prev.lower() not in DROPPED_TOOL_TOKENS else ""
    if rule == "uuid":
        base = f"{stem}_uuid" if stem else "uuid"
    elif rule == "hex_digest":
        base = f"{stem}_hash" if stem else "hash"
    elif rule == "iso_date":
        base = f"{stem}_date" if stem else "date"
    else:
        base = f"{stem}_id" if stem else "id"

    base = _sanitize_identifier(base)
    candidate = base
    suffix = 2
    while candidate in used_names:
        candidate = f"{base}_{suffix}"
        suffix += 1
    used_names.add(candidate)
    return candidate


def _build_tool_name(
    method: str,
    segments: list[RouteSegmentEvidence],
    registry: set[str],
    max_len: int,
) -> str:
    literals: list[str] = []
    params: list[str] = []
    for seg in segments:
        if seg.kind == "literal":
            tok = seg.name.split(".", 1)[0].lower()
            if tok and tok not in DROPPED_TOOL_TOKENS and not VERSION_TOKEN_RE.match(tok):
                literals.append(_sanitize_identifier(tok))
        else:
            params.append(_sanitize_identifier(seg.name))

    parts = [method.lower(), *literals]
    if params:
        parts.extend(["by", *params])
    base = _sanitize_identifier("_".join(parts))[:max_len].rstrip("_") or "endpoint"
    candidate = base
    suffix = 2
    while candidate in registry:
        tail = f"_{suffix}"
        candidate = f"{base[: max_len - len(tail)].rstrip('_')}{tail}"
        suffix += 1
    registry.add(candidate)
    return candidate


def _split_path(path: str, max_segments: int) -> list[str]:
    parts = [p for p in path.strip("/").split("/") if p]
    if len(parts) > max_segments:
        raise ValueError("Route exceeds the configured segment limit")
    return parts


def build_intermediate_api_model(
    capture: SanitizedHarCapture,
    limits: HarProcessingLimits = DEFAULT_LIMITS,
) -> tuple[IntermediateApiModel, OfflineCassette]:
    """Derive an evidence-backed IntermediateApiModel and OfflineCassette from a sanitized HAR."""
    origin_counts: Counter[str] = Counter()
    for ex in capture.admitted_exchanges:
        origin_counts[ex.origin] += 1

    all_origins = sorted(origin_counts.keys())
    primary_origin = origin_counts.most_common(1)[0][0] if origin_counts else ""

    prefix_children: dict[tuple[str, tuple[str, ...]], set[str]] = {}
    for ex in capture.admitted_exchanges:
        raw_segs = _split_path(ex.path, limits.max_route_segments)
        norm_prefix: list[str] = []
        for seg in raw_segs:
            fmt = _classify_segment_format(seg)
            key = (ex.origin, tuple(norm_prefix))
            prefix_children.setdefault(key, set()).add(seg)
            if fmt is not None:
                norm_prefix.append(f"<{fmt}>")
            else:
                norm_prefix.append(seg)

    grouped: dict[tuple[str, str, tuple[str, ...]], list[SanitizedExchange]] = {}
    for ex in capture.admitted_exchanges:
        raw_segs = _split_path(ex.path, limits.max_route_segments)
        shape: list[str] = []
        norm_prefix = []
        for seg in raw_segs:
            fmt = _classify_segment_format(seg)
            siblings = prefix_children.get((ex.origin, tuple(norm_prefix)), set())
            if fmt is not None:
                shape.append(f"<{fmt}>")
                norm_prefix.append(f"<{fmt}>")
            else:
                shape.append(seg)
                norm_prefix.append(seg)
        grouped.setdefault((ex.origin, ex.method, tuple(shape)), []).append(ex)

    tool_registry: set[str] = set()
    endpoints: list[EndpointToolModel] = []
    cassette_entries: list[CassetteEntry] = []

    for (origin, method, shape), group_exchanges in sorted(
        grouped.items(), key=lambda item: (item[0][0], item[0][2], item[0][1])
    ):
        used_param_names: set[str] = set()
        segment_evidences: list[RouteSegmentEvidence] = []
        path_params: list[str] = []
        uncertainty_notes: list[str] = []
        template_parts: list[str] = []

        sample_seg_lists = [
            _split_path(ex.path, limits.max_route_segments) for ex in group_exchanges
        ]
        first_segs = sample_seg_lists[0] if sample_seg_lists else []

        for idx, token in enumerate(shape):
            observed_at_idx = sorted(
                {segs[idx] for segs in sample_seg_lists if idx < len(segs)}
            )
            if token.startswith("<") and token.endswith(">"):
                raw_rule = token[1:-1]
                param_name = _param_name_for_position(
                    first_segs, idx, raw_rule, used_param_names
                )
                path_params.append(param_name)
                template_parts.append("{" + param_name + "}")

                if raw_rule == "numeric":
                    if len(observed_at_idx) >= 2:
                        p_rule = "numeric_multi_sample"
                        conf = "verified_multi_sample"
                    else:
                        p_rule = "numeric_single_sample"
                        conf = "inferred_single_sample"
                        uncertainty_notes.append(
                            f"Segment {idx} ('{observed_at_idx[0]}') was templated as '{{{param_name}}}' "
                            "from a single observed numeric sample; verify whether it is a variable ID or fixed route literal."
                        )
                elif raw_rule == "slug_multi_sample":
                    p_rule = "slug_multi_sample"
                    conf = "verified_multi_sample"
                else:
                    p_rule = raw_rule
                    conf = (
                        "verified_multi_sample"
                        if len(observed_at_idx) >= 2
                        else "high_format_match"
                    )

                segment_evidences.append(
                    RouteSegmentEvidence(
                        segment_index=idx,
                        kind="parameter",
                        name=param_name,
                        parameter_rule=p_rule,  # type: ignore[arg-type]
                        confidence=conf,  # type: ignore[arg-type]
                        observed_values=observed_at_idx[:20],
                    )
                )
            else:
                template_parts.append(token)
                segment_evidences.append(
                    RouteSegmentEvidence(
                        segment_index=idx,
                        kind="literal",
                        name=token,
                        parameter_rule="none",
                        confidence="exact_literal",
                        observed_values=observed_at_idx[:5],
                    )
                )

        path_template = "/" + "/".join(template_parts) if template_parts else "/"
        conf_order = {
            "inferred_single_sample": 0,
            "high_format_match": 1,
            "verified_multi_sample": 2,
            "exact_literal": 3,
        }
        route_conf = min(
            (s.confidence for s in segment_evidences),
            key=lambda c: conf_order[c],
            default="exact_literal",
        )

        tool_name = _build_tool_name(
            method, segment_evidences, tool_registry, limits.max_tool_name_length
        )
        observed_variants = sorted({ex.path for ex in group_exchanges})

        all_q_names = sorted({qk for ex in group_exchanges for qk in ex.query_params.keys()})
        query_evidences: list[QueryParameterEvidence] = []
        for qk in all_q_names:
            samples_with_qk = [
                ex.query_params[qk] for ex in group_exchanges if qk in ex.query_params
            ]
            flat_vals: list[Any] = []
            for val_list in samples_with_qk:
                for v in val_list:
                    if NUMERIC_RE.match(v):
                        flat_vals.append(int(v))
                    elif v.lower() in ("true", "false"):
                        flat_vals.append(v.lower() == "true")
                    else:
                        flat_vals.append(v)
            q_schema = infer_json_schema(flat_vals, limits) or {"type": "string"}
            query_evidences.append(
                QueryParameterEvidence(
                    name=qk,
                    inferred_schema=q_schema,
                    observed_in_all_requests=(len(samples_with_qk) == len(group_exchanges)),
                    sample_count=len(samples_with_qk),
                )
            )

        req_mimes = sorted(
            {ex.request_content_type for ex in group_exchanges if ex.request_content_type}
        )
        req_bodies = [
            ex.request_body
            for ex in group_exchanges
            if ex.request_body_status in ("json", "form_urlencoded")
            and ex.request_body is not None
        ]
        req_schema = infer_json_schema(req_bodies, limits) if req_bodies else None

        resp_statuses = sorted({ex.status for ex in group_exchanges})
        resp_mimes = sorted(
            {ex.response_content_type for ex in group_exchanges if ex.response_content_type}
        )
        resp_schemas_by_status: dict[str, dict[str, Any]] = {}
        for st in resp_statuses:
            st_bodies = [
                ex.response_body
                for ex in group_exchanges
                if ex.status == st
                and ex.response_body_status == "json"
                and ex.response_body is not None
            ]
            if st_bodies:
                resp_schemas_by_status[str(st)] = infer_json_schema(st_bodies, limits)

        is_state_changing = method.upper() in ("POST", "PUT", "PATCH", "DELETE")
        if is_state_changing:
            uncertainty_notes.append(
                f"State-changing method ({method}); offline cassette replays recorded responses without server-side persistence."
            )

        endpoints.append(
            EndpointToolModel(
                tool_name=tool_name,
                method=method,
                origin=origin,
                path_template=path_template,
                route_confidence=route_conf,  # type: ignore[arg-type]
                segments=segment_evidences,
                observed_path_variants=observed_variants,
                path_parameters=path_params,
                query_parameters=query_evidences,
                request_content_types=req_mimes,
                request_body_schema=req_schema,
                response_statuses=resp_statuses,
                response_content_types=resp_mimes,
                response_schemas_by_status=resp_schemas_by_status,
                evidence_ordinals=[ex.ordinal for ex in group_exchanges],
                is_state_changing=is_state_changing,
                uncertainty_notes=uncertainty_notes,
            )
        )

        for ex in group_exchanges:
            cassette_entries.append(
                CassetteEntry(
                    ordinal=ex.ordinal,
                    tool_name=tool_name,
                    method=ex.method,
                    origin=ex.origin,
                    path=ex.path,
                    path_template=path_template,
                    query_params=ex.query_params,
                    request_body=ex.request_body,
                    status=ex.status,
                    response_headers=ex.response_headers,
                    response_content_type=ex.response_content_type,
                    response_body=ex.response_body,
                )
            )

    cassette_entries.sort(key=lambda c: c.ordinal)

    model = IntermediateApiModel(
        source_filename=capture.source_filename,
        primary_origin=primary_origin,
        all_origins=all_origins,
        endpoints=endpoints,
        redaction_summary=capture.redaction_summary,
    )
    cassette = OfflineCassette(
        source_filename=capture.source_filename,
        entries=cassette_entries,
    )
    return model, cassette

    return candidate

    return {"type": sorted_types}
