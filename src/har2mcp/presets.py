"""Separately scoped domain filter presets for common self-hosted and developer APIs."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DomainPreset:
    """Curated origin and path filter rules for a known API service."""

    name: str
    description: str
    path_prefixes: tuple[str, ...]
    ignored_paths: tuple[str, ...] = ()


BUILTIN_PRESETS: dict[str, DomainPreset] = {
    "github": DomainPreset(
        name="github",
        description="GitHub REST & GraphQL APIs",
        path_prefixes=("/repos/", "/users/", "/orgs/", "/issues", "/search/", "/graphql"),
        ignored_paths=("/_private/", "/assets/"),
    ),
    "gitea": DomainPreset(
        name="gitea",
        description="Self-hosted Gitea / Forgejo API v1",
        path_prefixes=("/api/v1/",),
        ignored_paths=("/assets/", "/avatars/"),
    ),
    "immich": DomainPreset(
        name="immich",
        description="Self-hosted Immich photo management API",
        path_prefixes=("/api/",),
        ignored_paths=("/_app/",),
    ),
    "homeassistant": DomainPreset(
        name="homeassistant",
        description="Home Assistant REST API",
        path_prefixes=("/api/",),
        ignored_paths=("/frontend_latest/", "/static/"),
    ),
}
