#!/usr/bin/env python3
"""Run Forge with a fixture-specific config written outside the repository."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parent
fixture = Path(os.environ["WIRE_FIXTURE"]).resolve(strict=True)
output = Path(os.environ["FOUNDRY_OUT"]).resolve()
config = output.parent / "fixture-config" / "foundry.toml"
if config.is_relative_to(root.parents[2]):
    raise RuntimeError("Set FOUNDRY_OUT outside the repository")
config.parent.mkdir(parents=True, exist_ok=True)
text = (root / "foundry.toml").read_text()
text = text.replace('src = "src"', "src = " + json.dumps(str(root / "src")))
text = text.replace('test = "test"', "test = " + json.dumps(str(root / "test")))
text = text.replace("fs_permissions = []", 'fs_permissions = [{ access = "read", path = ' + json.dumps(str(fixture)) + " }]")
config.write_text(text)
subprocess.run([sys.executable, str(root / "test-compiler.py"), str(fixture)], check=True)
forge = shutil.which("forge")
if not forge:
    raise RuntimeError("Put the Foundry bin directory on PATH")
sys.exit(subprocess.call([forge, "test", "--root", str(root), "--config-path", str(config), *sys.argv[1:]]))
