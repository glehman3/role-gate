"""RBAC YAML and matrix validation."""
from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class Issue:
    severity: str
    code: str
    message: str

    def to_dict(self) -> dict:
        return {"severity": self.severity, "code": self.code, "message": self.message}


def _load_roles_doc(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("roles file must be a YAML mapping")
    return data


def _expand_role_permissions(
    role_name: str,
    roles: dict[str, Any],
    cache: dict[str, set[str]],
    stack: list[str],
) -> set[str]:
    if role_name in cache:
        return cache[role_name]
    if role_name in stack:
        raise ValueError(f"Inheritance cycle: {' -> '.join(stack + [role_name])}")

    cfg = roles.get(role_name)
    if not isinstance(cfg, dict):
        return set()

    perms: set[str] = set()
    inherits = cfg.get("inherits")
    if inherits:
        parent = str(inherits).strip()
        perms |= _expand_role_permissions(parent, roles, cache, stack + [role_name])

    for p in cfg.get("permissions") or []:
        perms.add(str(p).strip())
    cache[role_name] = perms
    return perms


def validate_roles_yaml(path: Path) -> dict[str, Any]:
    issues: list[Issue] = []
    doc = _load_roles_doc(path)

    declared = doc.get("permissions") or []
    if not isinstance(declared, list):
        issues.append(Issue("error", "invalid_permissions", "`permissions` must be a list"))
        declared = []

    declared_set = {str(p).strip() for p in declared if str(p).strip()}
    if len(declared_set) != len(declared):
        issues.append(Issue("error", "duplicate_permissions", "Duplicate entries in top-level `permissions`"))

    roles = doc.get("roles") or {}
    if not isinstance(roles, dict) or not roles:
        issues.append(Issue("error", "no_roles", "`roles` must be a non-empty mapping"))
        return {"path": str(path), "issues": [i.to_dict() for i in issues], "ok": False}

    effective: dict[str, list[str]] = {}
    try:
        cache: dict[str, set[str]] = {}
        for role_name in roles:
            effective[role_name] = sorted(
                _expand_role_permissions(role_name, roles, cache, [])
            )
    except ValueError as exc:
        issues.append(Issue("error", "inheritance_cycle", str(exc)))
        effective = {}

    all_used: set[str] = set()
    for role_name, perms in effective.items():
        all_used |= set(perms)
        unknown = sorted(set(perms) - declared_set)
        if unknown:
            issues.append(
                Issue(
                    "error",
                    "unknown_permission",
                    f"Role '{role_name}' references undefined permission(s): {', '.join(unknown)}",
                )
            )

    orphans = sorted(declared_set - all_used)
    if orphans:
        issues.append(
            Issue(
                "warning",
                "unused_permission",
                f"Declared but unused permission(s): {', '.join(orphans)}",
            )
        )

    critical = doc.get("critical_permissions") or []
    if isinstance(critical, list):
        for perm in critical:
            p = str(perm).strip()
            if p and not any(p in set(effective.get(r, [])) for r in effective):
                issues.append(
                    Issue(
                        "warning",
                        "uncovered_critical",
                        f"Critical permission '{p}' not granted to any role",
                    )
                )

    errors = [i for i in issues if i.severity == "error"]
    return {
        "path": str(path),
        "roles": list(roles.keys()),
        "effective_permissions": effective,
        "issues": [i.to_dict() for i in issues],
        "ok": len(errors) == 0,
    }


def validate_matrix_csv(matrix_path: Path, roles_path: Path) -> dict[str, Any]:
    role_report = validate_roles_yaml(roles_path)
    if not role_report.get("ok"):
        return {
            "path": str(matrix_path),
            "issues": [{"severity": "error", "code": "roles_invalid", "message": "Fix roles YAML first"}],
            "ok": False,
        }

    effective = role_report.get("effective_permissions") or {}
    issues: list[Issue] = []

    with open(matrix_path, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return {"path": str(matrix_path), "issues": [{"severity": "error", "code": "empty", "message": "Empty matrix"}], "ok": False}

        required = {"role", "permission", "expected"}
        missing_cols = required - {c.strip().lower() for c in reader.fieldnames}
        if missing_cols:
            issues.append(
                Issue("error", "missing_columns", f"Matrix missing columns: {', '.join(sorted(missing_cols))}")
            )
            return {"path": str(matrix_path), "issues": [i.to_dict() for i in issues], "ok": False}

        col_map = {k.strip().lower(): k for k in reader.fieldnames}
        for row_num, row in enumerate(reader, start=2):
            role = (row.get(col_map["role"]) or "").strip()
            perm = (row.get(col_map["permission"]) or "").strip()
            expected = (row.get(col_map["expected"]) or "").strip().lower()

            if role not in effective:
                issues.append(Issue("error", "unknown_role", f"Line {row_num}: unknown role '{role}'"))
                continue
            if expected not in ("allow", "deny"):
                issues.append(Issue("error", "bad_expected", f"Line {row_num}: expected must be allow or deny"))
                continue

            has_perm = perm in set(effective.get(role, []))
            actual = "allow" if has_perm else "deny"
            if actual != expected:
                issues.append(
                    Issue(
                        "error",
                        "matrix_mismatch",
                        f"Line {row_num}: role '{role}' + '{perm}' expected {expected}, got {actual}",
                    )
                )

    errors = [i for i in issues if i.severity == "error"]
    return {
        "path": str(matrix_path),
        "roles_file": str(roles_path),
        "issues": [i.to_dict() for i in issues],
        "ok": len(errors) == 0,
    }
