# Validation status

Before publication, the revised Python files were parsed with Python's AST parser without importing or executing the project. This is syntax validation only.

The historical local report said ten tests passed, but its socket monkeypatch did not establish OS-enforced network isolation. That report and its machine paths are not included as current proof.

No Docker runtime is available in the local task environment, so the target's runtime suite was not executed locally. Canonical verification is the Isolated checks GitHub Actions job, which provisions dependencies separately and then runs the Python tests, TypeScript compilation and Python package build inside a constrained container.

## Verified hosted result

[Isolated checks run 41525643029](https://github.com/jaspreet9kaur/har2mcp/actions/runs/41525643029) succeeded for implementation commit `2b0234868df54c54055c687e92508920dc534aff` on 2026-11-03 (Asia/Calcutta).

The inspected log reports **22 tests, zero failures, zero errors and zero skips**. This includes the original adapted cases, 11 publication regressions and a TypeScript test that typechecks normal and hostile-name generated clients. The package build produced both an sdist and a wheel for 0.1.0a1 inside disposable scratch. Those target-generated build files were not promoted to retained release artifacts.

The executed container command used network none, a read-only root and source, a nonroot user, no Linux capabilities, no-new-privileges, an empty allowlisted process environment, 512 MiB memory, one CPU, 64 processes, file-size and open-file limits, 64 MiB scratch, CPU time and a wall-clock deadline. The tests do not themselves prove every sandbox implementation property; the job configuration and successful execution establish which controls were requested and applied by Docker. Dependency/image provisioning happened before the isolated run with network access.

Private vulnerability reporting was enabled and its saved UI state verified. No test report was sent, so notification delivery and maintainer response are untested.

Unverified checks include transitive/OS/development dependency advisories, live-network behavior (unsupported), real user feedback, Windows/macOS runtime compatibility and private reporting notification delivery. No complete security-audit claim is made.
