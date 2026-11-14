#!/usr/bin/env python3
"""Run the complete acceptance suite using only disposable, simulated accounts.

Use the development environment: pip install -e '.[dev,browser-tests]'
Then: python -m playwright install chromium
      python scripts/acceptance.py --docker
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def source_fingerprint() -> str:
    paths = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT
    ).decode().split("\0")
    files = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
             for name in sorted(filter(None, paths)) if (ROOT / name).is_file()}
    return hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", action="store_true", help="also build and test the hardened container")
    parser.add_argument("--report-dir", type=Path, default=ROOT / "run" / "acceptance")
    args = parser.parse_args()
    output = args.report_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "junit.xml").unlink(missing_ok=True)
    report = {"started": datetime.now(timezone.utc).isoformat(), "python": sys.version.split()[0],
              "platform": platform.platform(), "mode": "simulated", "docker": args.docker, "checks": []}
    image = None

    def check(name: str, command: list[str], env=None) -> None:
        print(f"\n[{name}] {' '.join(command)}", flush=True)
        began = time.monotonic()
        log = output / f"{name}.log"
        with log.open("w", encoding="utf-8") as saved:
            process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True)
            for line in process.stdout:
                saved.write(line)
                saved.flush()
                print(line, end="", flush=True)
            code = process.wait()
        report["checks"].append({"name": name, "exit_code": code,
                                  "seconds": round(time.monotonic() - began, 2), "log": log.name})
        if code:
            raise RuntimeError(f"{name} failed (exit {code}); see {log}")

    try:
        for package in ("pytest", "playwright"):
            if importlib.util.find_spec(package) is None:
                raise RuntimeError("Install the acceptance dependencies: pip install -e '.[dev,browser-tests]'")
        from playwright.sync_api import sync_playwright
        with sync_playwright() as driver:
            if not Path(driver.chromium.executable_path).exists():
                raise RuntimeError("Install the test browser: python -m playwright install chromium")
        report["commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        report["dirty"] = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT))
        report["source_sha256"] = source_fingerprint()
        check("dependencies", [sys.executable, "-m", "pip", "check"])
        check("diff", ["git", "diff", "--check"])
        env = os.environ.copy()
        env.pop("AGW_TEST_IMAGE", None)
        env["AGW_TEST_ARTIFACTS"] = str(output / "screenshots")
        if args.docker:
            image = "agent-gateway:acceptance-" + uuid.uuid4().hex[:12]
            check("compose", ["docker", "compose", "-f", "deploy/docker-compose.yml", "config", "--quiet"])
            check("image", ["docker", "build", "-t", image, "."])
            env["AGW_TEST_IMAGE"] = image
        junit = output / "junit.xml"
        check("pytest", [sys.executable, "-m", "pytest", "-v", "-x", "--tb=short", "-o", "faulthandler_timeout=120", f"--junitxml={junit}"], env=env)
        if source_fingerprint() != report["source_sha256"]:
            raise RuntimeError("Source changed during acceptance; rerun against a stable snapshot")
        report["status"] = "passed"
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        report["status"], report["error"] = "failed", str(exc)
        print(str(exc), file=sys.stderr)
    finally:
        junit = output / "junit.xml"
        if junit.exists():
            suites = ET.parse(junit).getroot().iter("testsuite")
            counts = {key: 0 for key in ("tests", "failures", "errors", "skipped")}
            for suite in suites:
                for key in counts:
                    counts[key] += int(suite.get(key, 0))
            report["tests"] = counts
        if image:
            subprocess.run(["docker", "image", "rm", image], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        report["finished"] = datetime.now(timezone.utc).isoformat()
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"\nAcceptance {report['status']}: {output / 'report.json'}")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
