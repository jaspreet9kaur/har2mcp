# Changelog

## 0.1.0a1 — initial public alpha

- Portable source installation and contribution workflow.
- Offline-only MCP and generated TypeScript clients; live HTTP refused.
- Exact recorded-request matching; missing resources no longer return another sample.
- Generated code no longer embeds untrusted captures in executable comments.
- New output directories required; existing output is not silently overwritten.
- Bounded JSON parsing and rejection diagnostics without original long URLs.
- OpenAPI collisions across origins rejected; operation origins preserved.
- API comparisons keep origins distinct, and route segment limits fail explicitly.
- Regression tests, generated TypeScript checks and isolated CI package build.

No adoption, external contributors, full security audit or sponsorship eligibility is claimed.
