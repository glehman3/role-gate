# role-gate

[![CI](https://github.com/glehman3/role-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/glehman3/role-gate/actions/workflows/ci.yml)

Validate **RBAC role definitions** and optional **allow/deny matrices** — inheritance expansion, unknown permissions, cycles, and critical-permission coverage warnings.

## Quick start

```bash
pip install .
role-gate validate examples/roles.yaml
role-gate test examples/matrix.csv --roles examples/roles.yaml
```

## roles.yaml shape

```yaml
permissions:
  - read:records
  - write:records

critical_permissions:
  - write:records

roles:
  admin:
    permissions: [read:records, write:records]
  editor:
    inherits: viewer
    permissions: [write:records]
  viewer:
    permissions: [read:records]
```

## Matrix CSV

| role | permission | expected |
|------|------------|----------|
| editor | write:records | allow |
| viewer | write:records | deny |

## Scope

Generic demo roles only — not tied to any employer system. Illustrates API/RBAC testing discipline for portfolio review.

## License

MIT
