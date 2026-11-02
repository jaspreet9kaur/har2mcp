# Contributing

Please start with a real reproducible problem, a small proposed change and a synthetic fixture. Do not send automated bulk issues or PRs to other projects.

## Setup

Use Python 3.11+ and a virtual environment. Clone the repository and run `python -m pip install -e .`. Installation needs access to the package registry; the tool itself operates offline.

## Tests

The canonical runtime check is `.github/workflows/ci.yml`: it provisions the dependencies using `.ci/Dockerfile`, then runs tests and a package build inside a constrained, network-disabled Docker container. Read that workflow before running it locally. Docker is optional for ordinary tool use, but needed to reproduce these isolation claims.

For a trusted local checkout, `python run_verification.py` runs the Python tests and prints their results. This command itself does not enforce OS isolation. The TypeScript test skips unless `HAR2MCP_TSC` identifies a compiler; canonical CI requires that compiler and typechecks normal and hostile-name examples. Report skipped tests honestly.

Keep generated build artifacts in disposable scratch storage. Tests must not contact APIs or use ambient credentials. Never disable the CI sandbox merely to make a test pass.

## Fixtures

All fixtures must be invented and use `*.synthetic.har`. Use reserved `.example`/`.invalid` domains and clearly fictional credential values. A sanitized real capture is not automatically appropriate for a public issue. Describe a real-world problem using a fictional reproduction.

## Pull requests

Create a feature branch, explain the problem and resulting behavior, add relevant regressions and wait for CI. Attribute reused material and preserve licenses. Document uncertainty rather than treating sampled behavior as a complete server contract.

Before adding remote calls, automatic writes, new credential handling or a hosted service, discuss a design and its trust boundaries. This release intentionally refuses live HTTP.
