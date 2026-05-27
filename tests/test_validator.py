from pathlib import Path

import pytest

from role_gate.validator import validate_matrix_csv, validate_roles_yaml

ROOT = Path(__file__).parent.parent
ROLES = ROOT / "examples" / "roles.yaml"
MATRIX = ROOT / "examples" / "matrix.csv"
BAD = ROOT / "examples" / "roles_bad.yaml"


def test_roles_valid():
    report = validate_roles_yaml(ROLES)
    assert report["ok"]


def test_roles_cycle_fails():
    report = validate_roles_yaml(BAD)
    assert not report["ok"]


def test_matrix_passes():
    report = validate_matrix_csv(MATRIX, ROLES)
    assert report["ok"]
