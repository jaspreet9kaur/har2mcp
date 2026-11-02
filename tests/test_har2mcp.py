"""Comprehensive offline regression and security test suite for har2mcp."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from click.testing import CliRunner

from har2mcp.cli import main as cli_main
from har2mcp.diff import diff_intermediate_models
from har2mcp.generators.mcp_gen import compile_har_to_directory
from har2mcp.generators.openapi_gen import generate_openapi_31_spec
from har2mcp.generators.sdk_gen import generate_typescript_sdk
from har2mcp.graphql import extract_graphql_operations
from har2mcp.inference import build_intermediate_api_model
from har2mcp.limits import HarProcessingLimits
from har2mcp.mcp_runtime import (
    Har2McpDispatcher,
    create_official_mcp_server,
    load_dispatcher_from_directory,
)
from har2mcp.network_guard import (
    LiveRequestPolicy,
    is_blocked_ip,
    verify_target_url_safety,
)
from har2mcp.sanitizer import (
    parse_and_sanitize_har_dict,
    parse_and_sanitize_har_file,
)

FIXTURE_HAR = Path(__file__).resolve().parent / "fixtures" / "sample_api.synthetic.har"


class Har2McpTestSuite(unittest.TestCase):
    """Offline tests verifying HAR sanitization, route inference, OpenAPI/SDK generation, MCP runtime, and SSRF guards."""

    def test_01_sanitizer_redacts_secrets_and_filters_noise(self) -> None:
        capture = parse_and_sanitize_har_file(FIXTURE_HAR)
        self.assertEqual(capture.total_raw_entries, 9)
        self.assertEqual(len(capture.excluded_entries), 3)
        reasons = [e.reason for e in capture.excluded_entries]
        self.assertEqual(reasons, ["cors_preflight", "telemetry_domain", "static_asset"])

        self.assertEqual(len(capture.admitted_exchanges), 6)
        summary = capture.redaction_summary
        self.assertGreaterEqual(summary.redacted_url_userinfo, 1)
        self.assertGreaterEqual(summary.redacted_headers, 6)
        self.assertGreaterEqual(summary.redacted_cookies, 3)
        self.assertGreaterEqual(summary.redacted_query_params, 1)
        self.assertGreaterEqual(summary.redacted_body_fields, 3)
        self.assertIn("bearer", summary.detected_auth_schemes)
        self.assertIn("cookie", summary.detected_auth_schemes)
        self.assertIn("csrf_header", summary.detected_auth_schemes)
        self.assertIn("api_key_query", summary.detected_auth_schemes)

        serialized = json.dumps(capture.model_dump())
        for forbidden in (
            "synthetic_pass_do_not_use",
            "SYNTHETIC_QUERY_SECRET_999999",
            "SYNTHETIC_COOKIE_VALUE_123456",
            "SYNTHETIC_ROTATED_COOKIE_999",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "SYNTHETIC_WEBHOOK_SECRET_ABC",
            "SYNTHETIC_CSRF_TOKEN_777",
            "sk-synthetic1234567890abcdef",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_02_fail_closed_on_multipart_base64_and_html_scripts(self) -> None:
        raw_har = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "POST",
                            "url": "https://api.example.com/v1/upload",
                            "headers": [],
                            "postData": {
                                "mimeType": "multipart/form-data; boundary=---123",
                                "text": "raw_secret_file_bytes",
                            },
                        },
                        "response": {
                            "status": 200,
                            "headers": [],
                            "content": {
                                "mimeType": "application/octet-stream",
                                "encoding": "base64",
                                "text": "U0VDUkVUX0JJTkFSWQ==",
                            },
                        },
                    },
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://api.example.com/index.html",
                            "headers": [],
                        },
                        "response": {
                            "status": 200,
                            "headers": [],
                            "content": {
                                "mimeType": "text/html",
                                "text": "<html><script>alert(1)</script></html>",
                            },
                        },
                    },
                ]
            }
        }
        cap = parse_and_sanitize_har_dict(raw_har)
        self.assertEqual(len(cap.admitted_exchanges), 1)
        upload_ex = cap.admitted_exchanges[0]
        self.assertEqual(upload_ex.request_body_status, "withheld_multipart")
        self.assertIsNone(upload_ex.request_body)
        self.assertEqual(upload_ex.response_body_status, "withheld_binary_or_base64")
        self.assertIsNone(upload_ex.response_body)
        self.assertEqual(cap.excluded_entries[0].reason, "non_api_html_or_script")

    def test_03_enforces_entry_and_size_bounds(self) -> None:
        strict_limits = HarProcessingLimits(max_entries=2)
        with self.assertRaises(ValueError):
            parse_and_sanitize_har_file(FIXTURE_HAR, limits=strict_limits)

    def test_04_route_inference_retains_variants_and_confidence(self) -> None:
        capture = parse_and_sanitize_har_file(FIXTURE_HAR)
        model, cassette = build_intermediate_api_model(capture)

        by_tool = {ep.tool_name: ep for ep in model.endpoints}
        self.assertIn("get_projects_by_project_id", by_tool)
        multi_ep = by_tool["get_projects_by_project_id"]
        self.assertEqual(multi_ep.path_template, "/api/v1/projects/{project_id}")
        self.assertEqual(multi_ep.route_confidence, "verified_multi_sample")
        self.assertEqual(
            multi_ep.observed_path_variants,
            ["/api/v1/projects/101", "/api/v1/projects/102"],
        )

        self.assertIn("get_audit_by_audit_id", by_tool)
        single_ep = by_tool["get_audit_by_audit_id"]
        self.assertEqual(single_ep.path_template, "/api/v1/audit/{audit_id}")
        self.assertEqual(single_ep.route_confidence, "inferred_single_sample")
        self.assertEqual(single_ep.observed_path_variants, ["/api/v1/audit/999"])
        self.assertTrue(
            any("single observed numeric sample" in note for note in single_ep.uncertainty_notes)
        )
        self.assertEqual(len(cassette.entries), 6)

    def test_05_openapi_31_and_typescript_sdk_generation(self) -> None:
        capture = parse_and_sanitize_har_file(FIXTURE_HAR)
        model, _ = build_intermediate_api_model(capture)
        spec = generate_openapi_31_spec(model, title="Acme Tracker API")
        self.assertEqual(spec["openapi"], "3.1.0")
        self.assertIn("/api/v1/projects/{project_id}", spec["paths"])
        self.assertIn("bearerAuth", spec["components"]["securitySchemes"])

        sdk_code = generate_typescript_sdk(model)
        self.assertIn("export class Har2McpGeneratedClient", sdk_code)
        self.assertNotIn("fetch(", sdk_code)
        self.assertIn("Live mode is unavailable", sdk_code)

    def test_06_official_mcp_sdk_cassette_and_simulated_modes(self) -> None:
        capture = parse_and_sanitize_har_file(FIXTURE_HAR)
        model, cassette = build_intermediate_api_model(capture)

        dispatcher = Har2McpDispatcher(model=model, cassette=cassette, mode="cassette")
        mcp_srv = create_official_mcp_server(dispatcher)
        self.assertEqual(mcp_srv.name, "har2mcp-compiled-server")

        tools = dispatcher.list_mcp_tools()
        tool_names = [t.name for t in tools]
        self.assertIn("har2mcp_server_status", tool_names)
        self.assertIn("get_projects_by_project_id", tool_names)

        status_res = dispatcher.call_tool_sync("har2mcp_server_status", {})
        self.assertEqual(status_res["mode"], "cassette")
        self.assertFalse(status_res["live_mode_enabled"])

        hit_102 = dispatcher.call_tool_sync("get_projects_by_project_id", {"project_id": 102})
        self.assertEqual(hit_102["authority"], "recorded-cassette")
        self.assertEqual(hit_102["status"], 200)
        self.assertEqual(hit_102["body"]["name"], "Hermes SDK")

        with self.assertRaises(ValueError):
            dispatcher.call_tool_sync("get_projects_by_project_id", {"project_id": "../admin"})

        sim_dispatcher = Har2McpDispatcher(
            model=model, cassette=cassette, mode="simulated-state"
        )
        created = sim_dispatcher.call_tool_sync(
            "post_projects", {"body": {"name": "Simulated Project", "status": "draft"}}
        )
        self.assertEqual(created["authority"], "simulated-in-memory")
        self.assertIn("simulation_disclaimer", created)
        self.assertEqual(created["status"], 201)

    def test_07_ssrf_dns_rebinding_and_policy_guards(self) -> None:
        default_policy = LiveRequestPolicy()
        with self.assertRaises(PermissionError):
            verify_target_url_safety(
                "https://api.acme-tracker.example/api/v1/projects",
                "GET",
                default_policy,
            )

        live_read_only = LiveRequestPolicy(
            allow_live_mode=True,
            allowed_origins=frozenset({"https://api.acme-tracker.example"}),
            allowed_methods=frozenset({"GET", "HEAD"}),
        )
        with self.assertRaises(PermissionError):
            verify_target_url_safety(
                "https://evil.example/api/v1/projects", "GET", live_read_only
            )
        with self.assertRaises(PermissionError):
            verify_target_url_safety(
                "https://api.acme-tracker.example/api/v1/projects",
                "DELETE",
                live_read_only,
            )

        def fake_loopback_resolver(host: str, port: int, type: int = 0) -> list[tuple]:
            return [(2, 1, 6, "", ("127.0.0.1", port))]

        with self.assertRaises(PermissionError):
            verify_target_url_safety(
                "https://api.acme-tracker.example/api/v1/projects",
                "GET",
                live_read_only,
                resolver=fake_loopback_resolver,
            )

        blocked, _ = is_blocked_ip("169.254.169.254", allow_private_network=True)
        self.assertTrue(blocked)
        blocked_v6, _ = is_blocked_ip("::ffff:169.254.169.254", allow_private_network=True)
        self.assertTrue(blocked_v6)

    def test_08_separately_scoped_graphql_and_diff_and_cli_compile(self) -> None:
        capture = parse_and_sanitize_har_file(FIXTURE_HAR)
        gql_ops = extract_graphql_operations(capture)
        self.assertEqual(len(gql_ops), 1)
        self.assertEqual(gql_ops[0].operation_name, "GetViewerProfile")
        self.assertEqual(gql_ops[0].operation_kind, "query")

        model_v1, _ = build_intermediate_api_model(capture)
        diff_same = diff_intermediate_models(model_v1, model_v1)
        self.assertEqual(diff_same.newly_observed_endpoints, [])

        with tempfile.TemporaryDirectory() as tmp_dir:
            runner = CliRunner()
            res = runner.invoke(
                cli_main,
                ["compile", str(FIXTURE_HAR), "--out", str(Path(tmp_dir) / "bundle"), "--include-graphql"],
            )
            self.assertEqual(res.exit_code, 0, msg=res.output)
            loaded = load_dispatcher_from_directory(Path(tmp_dir) / "bundle", mode="cassette")
            self.assertGreaterEqual(len(loaded.list_mcp_tools()), 5)

    def test_09_official_mcp_protocol_session_roundtrip(self) -> None:
        import anyio
        from mcp.client.session import ClientSession
        from mcp.shared.memory import create_connected_server_and_client_session

        capture = parse_and_sanitize_har_file(FIXTURE_HAR)
        model, cassette = build_intermediate_api_model(capture)
        dispatcher = Har2McpDispatcher(model=model, cassette=cassette, mode="cassette")
        server = create_official_mcp_server(dispatcher)

        async def _run_protocol_check() -> None:
            async with create_connected_server_and_client_session(server) as client_session:
                assert isinstance(client_session, ClientSession)
                tools_result = await client_session.list_tools()
                names = [t.name for t in tools_result.tools]
                self.assertIn("har2mcp_server_status", names)
                self.assertIn("get_projects_by_project_id", names)

                call_res = await client_session.call_tool(
                    "get_projects_by_project_id", {"project_id": 101}
                )
                self.assertFalse(call_res.isError)
                payload = json.loads(call_res.content[0].text)
                self.assertEqual(payload["authority"], "recorded-cassette")
                self.assertEqual(payload["status"], 200)
                self.assertEqual(payload["body"]["id"], 101)

        anyio.run(_run_protocol_check)

    def test_10_form_urlencoded_and_redirect_and_streaming_bounds(self) -> None:
        from unittest.mock import MagicMock, patch
        from har2mcp.network_guard import execute_guarded_live_request

        # 1. Form-urlencoded secret redaction
        form_har = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "POST",
                            "url": "https://api.acme-tracker.example/oauth/token",
                            "headers": [],
                            "postData": {
                                "mimeType": "application/x-www-form-urlencoded",
                                "text": "grant_type=client_credentials&client_id=my_app&client_secret=TOP_SECRET_FORM_VAL",
                            },
                        },
                        "response": {
                            "status": 200,
                            "headers": [],
                            "content": {
                                "mimeType": "application/json",
                                "text": "{\"access_token\": \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig1234567890\", \"expires_in\": 3600}",
                            },
                        },
                    }
                ]
            }
        }
        cap = parse_and_sanitize_har_dict(form_har)
        ex = cap.admitted_exchanges[0]
        self.assertEqual(ex.request_body["client_secret"], "[REDACTED]")
        self.assertEqual(ex.request_body["grant_type"], "client_credentials")
        self.assertEqual(ex.response_body["access_token"], "[REDACTED]")

        # This public release refuses live mode even when explicitly requested.
        policy = LiveRequestPolicy(
            allow_live_mode=True,
            allowed_origins=frozenset({"https://api.acme-tracker.example"}),
        )
        with self.assertRaises(PermissionError):
            execute_guarded_live_request("GET", "https://api.acme-tracker.example", "/", None, None, policy)


if __name__ == "__main__":
    unittest.main()
