"""Regression fixtures for the publication changes; no real captures or network."""
import json
from pathlib import Path
import tempfile
import unittest

from har2mcp.cassette import CassetteReplayEngine
from har2mcp.generators.mcp_gen import compile_har_to_directory
from har2mcp.generators.openapi_gen import generate_openapi_31_spec
from har2mcp.generators.sdk_gen import generate_typescript_sdk
from har2mcp.inference import build_intermediate_api_model
from har2mcp.mcp_runtime import Har2McpDispatcher
from har2mcp.sanitizer import parse_and_sanitize_har_dict, parse_and_sanitize_har_file, _bounded_json

FIXTURE = Path(__file__).parent / "fixtures" / "sample_api.synthetic.har"


class PublicationTests(unittest.TestCase):
    def model(self):
        return build_intermediate_api_model(parse_and_sanitize_har_file(FIXTURE))

    def test_unknown_resource_never_returns_another_recorded_resource(self):
        model, cassette = self.model()
        endpoint = next(e for e in model.endpoints if e.tool_name == "get_projects_by_project_id")
        result = CassetteReplayEngine(cassette).replay_tool_call(endpoint, {"project_id": 999})
        self.assertFalse(result["matched"])
        self.assertEqual(result["status"], 404)

    def test_query_mismatch_is_not_treated_as_a_hit(self):
        model, cassette = self.model()
        endpoint = next(e for e in model.endpoints if e.tool_name == "get_projects_by_project_id")
        for entry in cassette.entries:
            if entry.tool_name == endpoint.tool_name:
                entry.query_params = {"unobserved": ["value"]}
        self.assertFalse(CassetteReplayEngine(cassette).replay_tool_call(endpoint, {"project_id": 101})["matched"])

    def test_body_mismatch_is_not_treated_as_a_hit(self):
        model, cassette = self.model()
        endpoint = next(e for e in model.endpoints if e.tool_name == "post_projects")
        self.assertFalse(CassetteReplayEngine(cassette).replay_tool_call(endpoint, {"body": {"different": True}})["matched"])

    def test_live_dispatcher_is_rejected_before_any_transport(self):
        model, cassette = self.model()
        with self.assertRaises(ValueError):
            Har2McpDispatcher(model, cassette, mode="live")

    def test_compile_does_not_overwrite_existing_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            sentinel = Path(temporary) / "keep.txt"
            sentinel.write_text("keep", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                compile_har_to_directory(FIXTURE, temporary)
            self.assertEqual(sentinel.read_text(), "keep")

    def test_invalid_input_does_not_create_an_output_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            broken = Path(temporary) / "broken.har"
            broken.write_text("{}", encoding="utf-8")
            output = Path(temporary) / "bundle"
            with self.assertRaises(ValueError):
                compile_har_to_directory(broken, output)
            self.assertFalse(output.exists())

    def test_long_rejected_url_does_not_leak_its_query(self):
        url = "https://example.com/?token=fictional-sensitive-value&pad=" + "x" * 5000
        capture = parse_and_sanitize_har_dict({"log": {"entries": [{"request": {"method": "GET", "url": url}, "response": {}}]}})
        self.assertNotIn("fictional-sensitive-value", capture.model_dump_json())

    def test_json_depth_guard_ignores_braces_in_strings(self):
        self.assertEqual(_bounded_json('{"text":"[[[[["}', 2), {"text": "[[[[["})
        with self.assertRaises(ValueError):
            _bounded_json("[" * 30 + "0" + "]" * 30, 24)

    def test_same_path_from_multiple_origins_is_not_silently_overwritten(self):
        model, _ = self.model()
        copy = model.endpoints[0].model_copy(deep=True)
        copy.origin = "https://second.example"
        copy.tool_name += "_second"
        model.endpoints.append(copy)
        with self.assertRaises(ValueError):
            generate_openapi_31_spec(model)

    def test_generated_code_keeps_captured_comment_terminators_as_data(self):
        model, _ = self.model()
        endpoint = model.endpoints[0]
        endpoint.path_template = '/x*/throw new Error("injected");/*'
        endpoint.segments = []
        output = generate_typescript_sdk(model)
        self.assertNotIn('throw new Error("injected")', output)
        self.assertNotIn("fetch(", output)
        self.assertNotIn("// Source HAR:", output)

    def test_openapi_operations_keep_their_observed_origin(self):
        model, _ = self.model()
        spec = generate_openapi_31_spec(model)
        for endpoint in model.endpoints:
            self.assertEqual(spec["paths"][endpoint.path_template][endpoint.method.lower()]["servers"], [{"url": endpoint.origin}])
