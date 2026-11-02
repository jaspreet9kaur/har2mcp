# Security

This is an early offline prototype. No production support promise, audit certification or response-time SLA is provided.

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/jaspreet9kaur/har2mcp/security/advisories/new) once enabled. Do not post real captures, credentials, personal records or exploit details in public issues. If that reporting form is unavailable, wait for a private route rather than posting sensitive details publicly.

Use a fictional fixture to explain an affected version, boundary, expected behavior and observed result. Redaction is heuristic; review artifacts manually. The scanner does not execute captured content, but imported captures and compiled bundles remain untrusted input. Run analysis on stable local copies under ordinary user privileges.

Live networking is unavailable. A previous local prototype inspected DNS before a separate HTTP-client resolution; that did not establish connection-bound protection. A future live mode needs a new transport and security review before becoming supported.
