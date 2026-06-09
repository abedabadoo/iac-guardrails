#!/usr/bin/env python3
"""Turn `conftest test --output json` results into an auditor-readable
compliance report, joined to the control matrix in controls/mapping.yaml.

Usage:
    conftest test plan.json -p policies/ --output json | python cli/report.py
    python cli/report.py --conftest-json results.json
    python cli/report.py plan.json            # runs conftest for you (needs conftest on PATH)
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_controls() -> dict[str, dict]:
    """Map Rego package -> control metadata. Optional dependency: PyYAML.

    Falls back to an empty matrix (report still renders, just without
    framework columns) so the CLI never hard-fails on a missing dep.
    """
    path = ROOT / "controls" / "mapping.yaml"
    try:
        import yaml  # type: ignore
    except ModuleNotFoundError:
        sys.stderr.write("note: PyYAML not installed; framework columns omitted\n")
        return {}
    data = yaml.safe_load(path.read_text()) or {}
    return {c["package"]: c for c in data.get("controls", [])}


def run_conftest(plan: str) -> list[dict]:
    proc = subprocess.run(
        ["conftest", "test", plan, "-p", str(ROOT / "policies"), "--output", "json"],
        capture_output=True,
        text=True,
    )
    if not proc.stdout:
        sys.stderr.write(proc.stderr)
        sys.exit(2)
    return json.loads(proc.stdout)


def collect_failures(results: list[dict]) -> list[dict]:
    failures = []
    for f in results:
        for kind in ("failures", "warnings"):
            for item in f.get(kind, []):
                failures.append(
                    {
                        "level": "block" if kind == "failures" else "warn",
                        "namespace": item.get("metadata", {}).get("package")
                        or item.get("namespace", ""),
                        "msg": item.get("msg", ""),
                    }
                )
    return failures


def render(failures: list[dict], controls: dict[str, dict]) -> str:
    lines = ["# Compliance Report", ""]
    if not failures:
        lines += ["✅ **All guardrails passed.** No control violations in this plan.", ""]
        return "\n".join(lines)

    lines += [
        f"❌ **{len(failures)} control violation(s) found.**",
        "",
        "| Level | Control | CIS | SOC 2 | NIST | Finding |",
        "|-------|---------|-----|-------|------|---------|",
    ]
    for f in failures:
        c = controls.get(f["namespace"], {})
        lines.append(
            "| {level} | {title} | {cis} | {soc2} | {nist} | {msg} |".format(
                level=f["level"],
                title=c.get("title", f["namespace"] or "—"),
                cis=c.get("cis", "—"),
                soc2=c.get("soc2", "—"),
                nist=c.get("nist", "—"),
                msg=f["msg"],
            )
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("plan", nargs="?", help="Terraform plan JSON (runs conftest for you)")
    ap.add_argument("--conftest-json", help="pre-computed `conftest --output json` file")
    args = ap.parse_args()

    if args.conftest_json:
        results = json.loads(Path(args.conftest_json).read_text())
    elif args.plan:
        results = run_conftest(args.plan)
    elif not sys.stdin.isatty():
        results = json.loads(sys.stdin.read())
    else:
        ap.error("provide a plan file, --conftest-json, or pipe conftest json on stdin")

    failures = collect_failures(results)
    print(render(failures, load_controls()))
    return 1 if any(f["level"] == "block" for f in failures) else 0


if __name__ == "__main__":
    raise SystemExit(main())
