"""Separately scoped opt-in in-memory CRUD simulation engine.

IMPORTANT EPISTEMIC BOUNDARY:
A recorded GET in a HAR file does NOT establish real server-side create, update,
delete, validation, or authorization semantics. This module is strictly opt-in
(--simulate-state) and tags every response with authority='simulated-in-memory'
and an explicit simulation disclaimer.
"""

from __future__ import annotations

import copy
from typing import Any

from har2mcp.cassette import CassetteReplayEngine, render_path_template
from har2mcp.models import EndpointToolModel, OfflineCassette

SIMULATION_DISCLAIMER = (
    "Simulated in-memory state derived heuristically from recorded HAR reads. "
    "A recorded GET does not establish real server create/update/delete validation, "
    "side effects, or authorization semantics."
)


class SimulatedStateEngine:
    """Opt-in in-memory state simulator layered over an OfflineCassette."""

    def __init__(self, cassette: OfflineCassette) -> None:
        self._fallback = CassetteReplayEngine(cassette)
        self._collections: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
        self._next_id = 10_000
        self._seed_from_cassette(cassette)

    def _seed_from_cassette(self, cassette: OfflineCassette) -> None:
        for entry in cassette.entries:
            if entry.method != "GET" or not (200 <= entry.status < 300):
                continue
            collection_name = self._collection_name_from_path(entry.path)
            if not collection_name:
                continue
            key = (entry.origin, collection_name)
            store = self._collections.setdefault(key, {})
            body = entry.response_body
            if isinstance(body, list):
                for item in body:
                    if isinstance(item, dict):
                        ent_id = self._extract_id(item)
                        if ent_id is not None:
                            store[ent_id] = copy.deepcopy(item)
            elif isinstance(body, dict):
                ent_id = self._extract_id(body)
                if ent_id is not None:
                    store[ent_id] = copy.deepcopy(body)

    @staticmethod
    def _extract_id(item: dict[str, Any]) -> str | None:
        for field in ("id", "uuid", "uid", "slug"):
            if field in item and item[field] is not None:
                return str(item[field])
        return None

    @staticmethod
    def _collection_name_from_path(path: str) -> str | None:
        parts = [p for p in path.strip("/").split("/") if p]
        filtered = [p for p in parts if p.lower() not in ("api", "apis", "v1", "v2", "v3")]
        return filtered[0].lower() if filtered else None

    def execute_simulated(
        self,
        endpoint: EndpointToolModel,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        args = arguments or {}
        path_args = {p: args.get(p) for p in endpoint.path_parameters}
        rendered_path = render_path_template(endpoint.path_template, path_args)
        collection = self._collection_name_from_path(rendered_path)

        if not collection:
            res = self._fallback.replay_tool_call(endpoint, args)
            return {
                **res,
                "authority": "simulated-in-memory",
                "simulation_disclaimer": SIMULATION_DISCLAIMER,
            }

        store = self._collections.setdefault((endpoint.origin, collection), {})
        method = endpoint.method.upper()
        body_payload = args.get("body") if isinstance(args.get("body"), dict) else {}
        param_id = (
            str(path_args[endpoint.path_parameters[0]])
            if endpoint.path_parameters
            else None
        )

        if method == "GET":
            if param_id is not None:
                if param_id in store:
                    return {
                        "authority": "simulated-in-memory",
                        "simulation_disclaimer": SIMULATION_DISCLAIMER,
                        "status": 200,
                        "body": copy.deepcopy(store[param_id]),
                    }
                return {
                    "authority": "simulated-in-memory",
                    "simulation_disclaimer": SIMULATION_DISCLAIMER,
                    "status": 404,
                    "body": {
                        "error": f"Simulated entity '{param_id}' not found in '{collection}'"
                    },
                }
            return {
                "authority": "simulated-in-memory",
                "simulation_disclaimer": SIMULATION_DISCLAIMER,
                "status": 200,
                "body": [copy.deepcopy(v) for v in store.values()],
            }

        if method == "POST":
            new_item = copy.deepcopy(body_payload)
            ent_id = self._extract_id(new_item)
            if ent_id is None:
                self._next_id += 1
                ent_id = str(self._next_id)
                new_item["id"] = self._next_id
            store[ent_id] = new_item
            return {
                "authority": "simulated-in-memory",
                "simulation_disclaimer": SIMULATION_DISCLAIMER,
                "status": 201,
                "body": copy.deepcopy(new_item),
            }

        if method in ("PUT", "PATCH") and param_id is not None:
            existing = store.get(param_id, {"id": param_id})
            updated = (
                {**existing, **copy.deepcopy(body_payload)}
                if method == "PATCH"
                else {"id": param_id, **copy.deepcopy(body_payload)}
            )
            store[param_id] = updated
            return {
                "authority": "simulated-in-memory",
                "simulation_disclaimer": SIMULATION_DISCLAIMER,
                "status": 200,
                "body": copy.deepcopy(updated),
            }

        if method == "DELETE" and param_id is not None:
            removed = store.pop(param_id, None)
            return {
                "authority": "simulated-in-memory",
                "simulation_disclaimer": SIMULATION_DISCLAIMER,
                "status": 200 if removed is not None else 404,
                "body": {"deleted": removed is not None, "id": param_id},
            }

        res = self._fallback.replay_tool_call(endpoint, args)
        return {
            **res,
            "authority": "simulated-in-memory",
            "simulation_disclaimer": SIMULATION_DISCLAIMER,
        }
