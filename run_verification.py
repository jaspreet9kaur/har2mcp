"""Run tests and print a summary. Network isolation belongs to the OS/container."""
import io
import json
from pathlib import Path
import sys
import unittest


def main():
    stream = io.StringIO()
    suite = unittest.defaultTestLoader.discover(str(Path(__file__).parent / "tests"))
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    print(stream.getvalue(), file=sys.stderr)
    print(json.dumps({"tests_run": result.testsRun, "failures": len(result.failures),
                      "errors": len(result.errors), "skipped": len(result.skipped),
                      "passed": result.wasSuccessful(), "network_isolation": "provided externally; not asserted by this script"}))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
