"""Separately scoped observational diff engine between two IntermediateApiModels.

EPISTEMIC NOTE:
Because HAR captures are finite runtime samples, an endpoint or property absent in
new.har is reported as 'not_observed_in_new_sample' rather than a guaranteed server removal.
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from har2mcp.models import IntermediateApiModel


class EndpointObservationDiff(BaseModel):
    """Observed differences between two HAR models for a single (method, path_template) pair."""

    model_config = ConfigDict(extra="forbid")

    origin: str = ""
    method: str
    path_template: str
    added_query_params: list[str] = Field(default_factory=list)
    unobserved_query_params: list[str] = Field(default_factory=list)
    added_response_statuses: list[int] = Field(default_factory=list)
    unobserved_response_statuses: list[int] = Field(default_factory=list)
    added_response_200_keys: list[str] = Field(default_factory=list)
    unobserved_response_200_keys: list[str] = Field(default_factory=list)


class ApiModelObservationDiff(BaseModel):
    """Comparison report between two HAR-derived IntermediateApiModels."""

    model_config = ConfigDict(extra="forbid")

    old_source: str
    new_source: str
    newly_observed_endpoints: list[str] = Field(default_factory=list)
    unobserved_in_new_sample: list[str] = Field(default_factory=list)
    changed_endpoints: list[EndpointObservationDiff] = Field(default_factory=list)
    epistemic_note: str = (
        "Comparison reflects differences between two finite HAR samples. "
        "An endpoint or field in 'unobserved_in_new_sample' means it was not exercised in the second recording, "
        "which does not by itself prove server-side removal."
    )


def _top_level_object_keys(schema: dict[str, Any] | None) -> set[str]:
    if not isinstance(schema, dict):
        return set()
    if schema.get("type") == "object" and isinstance(schema.get("properties"), dict):
        return set(schema["properties"].keys())
    if schema.get("type") == "array" and isinstance(schema.get("items"), dict):
        return _top_level_object_keys(schema["items"])
    return set()


def diff_intermediate_models(
    old_model: IntermediateApiModel,
    new_model: IntermediateApiModel,
) -> ApiModelObservationDiff:
    """Compare two IntermediateApiModel instances and report observed surface changes."""
    old_map = {(ep.origin, ep.method, ep.path_template): ep for ep in old_model.endpoints}
    new_map = {(ep.origin, ep.method, ep.path_template): ep for ep in new_model.endpoints}

    old_keys = set(old_map.keys())
    new_keys = set(new_map.keys())

    newly_observed = sorted(f"{m} {o}{p}" for (o, m, p) in (new_keys - old_keys))
    unobserved = sorted(f"{m} {o}{p}" for (o, m, p) in (old_keys - new_keys))

    changed: list[EndpointObservationDiff] = []
    for key in sorted(old_keys & new_keys):
        old_ep = old_map[key]
        new_ep = new_map[key]

        old_q = {q.name for q in old_ep.query_parameters}
        new_q = {q.name for q in new_ep.query_parameters}

        old_st = set(old_ep.response_statuses)
        new_st = set(new_ep.response_statuses)

        old_200_keys = _top_level_object_keys(old_ep.response_schemas_by_status.get("200"))
        new_200_keys = _top_level_object_keys(new_ep.response_schemas_by_status.get("200"))

        diff_entry = EndpointObservationDiff(
            origin=key[0],
            method=key[1],
            path_template=key[2],
            added_query_params=sorted(new_q - old_q),
            unobserved_query_params=sorted(old_q - new_q),
            added_response_statuses=sorted(new_st - old_st),
            unobserved_response_statuses=sorted(old_st - new_st),
            added_response_200_keys=sorted(new_200_keys - old_200_keys),
            unobserved_response_200_keys=sorted(old_200_keys - new_200_keys),
        )
        if (
            diff_entry.added_query_params
            or diff_entry.unobserved_query_params
            or diff_entry.added_response_statuses
            or diff_entry.unobserved_response_statuses
            or diff_entry.added_response_200_keys
            or diff_entry.unobserved_response_200_keys
        ):
            changed.append(diff_entry)

    return ApiModelObservationDiff(
        old_source=old_model.source_filename,
        new_source=new_model.source_filename,
        newly_observed_endpoints=newly_observed,
        unobserved_in_new_sample=unobserved,
        changed_endpoints=changed,
    )
