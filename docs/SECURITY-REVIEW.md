# Baseline release review

Scope: source review of the user's local implementation and publication changes, 2026-11-03. This is not a comprehensive audit or penetration test. Test execution evidence is recorded separately in VALIDATION.md: 22 cases passed in the isolated hosted CI run, including generated TypeScript checks and the Python package build.

| Category | Applicability and evidence |
| --- | --- |
| Injection / code generation | Source-reviewed. Captures enter JSON, types and quoted strings rather than raw code comments. Regression cases and TypeScript compilation are included in CI; results must be checked before claiming execution coverage. |
| SQL / CSRF | Not applicable: no SQL database, cookie-authenticated web server or browser mutation endpoint. |
| XSS / untrusted output | No HTML application. JSON and MCP responses remain untrusted data. Consumers must escape output and must not follow instructions embedded in recorded content. |
| Uploads / parser bounds | No upload service. HAR bytes, entries, body size, nesting, headers and route segments are bounded. Bounds do not guarantee constant memory. Compilation refuses existing output directories; concurrent hostile filesystem replacement is outside the current isolation claim. |
| SSRF / redirects / DNS rebinding | Live HTTP transport removed from public interfaces and refused by the dispatcher and transport stub. Policy-inspection helpers are experimental and are not claimed as connection-bound protection. |
| Authentication / IDOR / MFA / passwords / tenant rows | Not applicable to local offline CLI and stdio service. Recorded authorization behavior does not establish actual authorization rules. A future hosted service needs authentication and tenant isolation. |
| Rate limiting / resource limits | No public service. Parser limits are source-reviewed. Canonical CI uses OS-level memory/CPU/process/file-size/disk and wall-clock limits; ordinary local invocation has only application limits. |
| Secrets / JWT / browser storage / defaults | No live credentials required or consumed. Known sensitive headers, JSON/form keys and token patterns are heuristically scrubbed. Custom secrets, ordinary strings, path identifiers, GraphQL literals, headers and personal data may remain. No anonymity or safe-to-share guarantee. No login/default password or browser storage exists. |
| CORS / webhook signatures / source maps | Not applicable: no HTTP service, webhook receiver or web bundle. |
| Dependencies | Official PyPI metadata for the initially pinned direct packages was checked on 2026-11-03: no listed advisories or yanked releases were returned. The pydantic pin was updated to 2.14.2, and unused direct HTTP/URI dependencies removed. This is not a transitive vulnerability scan; container bases, OS libraries, MCP's transitive HTTP dependencies and development tools are not certified advisory-free. |
| CI trust boundary | Dependency/image provisioning has network access and is separate from target test/build execution. Tests/build run with network none, read-only source/toolchain, empty allowlisted environment, no capabilities, nonroot user, bounded scratch and resources. No secrets are passed; checkout persistence is disabled. Changes to the workflow or Dockerfile require review. |

Remaining: private-report notification delivery, conduct-reporting contacts, complete dependency/advisory coverage, package-install smoke checks in broader environments and an independent adversarial audit. A public alpha is not described as production-secure.
