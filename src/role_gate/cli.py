"""role-gate CLI."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .validator import validate_matrix_csv, validate_roles_yaml


def _print_report(report: dict, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(report, indent=2))
        return
    lines = [f"# role-gate report", "", f"**Path:** {report.get('path', '')}", ""]
    if report.get("ok"):
        lines.append("**Result:** OK")
    else:
        lines.append("**Result:** FAILED")
    for issue in report.get("issues") or []:
        lines.append(f"- [{issue['severity']}] `{issue['code']}` — {issue['message']}")
    print("\n".join(lines))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate RBAC roles YAML and permission matrices.")
    parser.add_argument("--format", choices=("md", "json"), default="md")
    sub = parser.add_subparsers(dest="command", required=True)

    val = sub.add_parser("validate", help="Validate roles.yaml")
    val.add_argument("roles", type=Path)

    test = sub.add_parser("test", help="Run allow/deny matrix against roles.yaml")
    test.add_argument("matrix", type=Path)
    test.add_argument("--roles", type=Path, default=Path("examples/roles.yaml"))

    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            report = validate_roles_yaml(args.roles)
        else:
            report = validate_matrix_csv(args.matrix, args.roles)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    _print_report(report, args.format)
    return 0 if report.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
