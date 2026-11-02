"""Typecheck generated output inside the isolated CI container."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from har2mcp.generators.sdk_gen import generate_typescript_sdk
from har2mcp.inference import build_intermediate_api_model
from har2mcp.sanitizer import parse_and_sanitize_har_file


@unittest.skipUnless(os.environ.get("HAR2MCP_TSC"), "TypeScript compiler not configured; isolated CI requires it")
class TypeScriptTests(unittest.TestCase):
    def test_generated_clients_typecheck_with_hostile_captured_names(self):
        fixture = Path(__file__).parent / "fixtures" / "sample_api.synthetic.har"
        model, _ = build_intermediate_api_model(parse_and_sanitize_har_file(fixture))
        with tempfile.TemporaryDirectory() as temporary:
            for variant in ("normal", "hostile"):
                if variant == "hostile":
                    model.source_filename = "bad\n*/throw new Error('oops');/*.har"
                    for endpoint in model.endpoints:
                        endpoint.path_template = "/x*/throw new Error('oops');/*"
                        for segment in endpoint.segments:
                            if segment.kind == "literal":
                                segment.name += "*/throw new Error('oops');/*"
                target = Path(temporary) / (variant + ".ts")
                target.write_text(generate_typescript_sdk(model), encoding="utf-8")
                result = subprocess.run(["node", os.environ["HAR2MCP_TSC"], "--strict", "--noEmit", "--target", "es2020", str(target)],
                                        capture_output=True, text=True, timeout=30, check=False)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
