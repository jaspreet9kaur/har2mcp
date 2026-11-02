"""CI orchestration inside the constrained container. No retained build artifacts."""
from pathlib import Path
import importlib.metadata
import os
import shutil
import subprocess
import sys

if os.environ.get("HAR2MCP_TSC") != "/opt/typescript/bin/tsc":
    raise SystemExit("Isolated CI requires the configured TypeScript compiler")
result = subprocess.run([sys.executable, "-B", "/repo/run_verification.py"], timeout=100, check=False)
if result.returncode:
    raise SystemExit(result.returncode)

# setuptools builds can write beside source: use a disposable copy inside scratch.
source = Path("/scratch/package")
source.mkdir()
for name in ("pyproject.toml", "README.md", "LICENSE"):
    shutil.copyfile(Path("/repo") / name, source / name)
shutil.copytree("/repo/src", source / "src")
subprocess.run([sys.executable, "-m", "build", "--no-isolation", "--outdir", "/scratch/dist", str(source)], check=True, timeout=60)
wheels = list(Path("/scratch/dist").glob("*.whl"))
if len(wheels) != 1:
    raise SystemExit("Expected exactly one wheel")
print("Package build smoke check passed; generated artifacts are disposable")
