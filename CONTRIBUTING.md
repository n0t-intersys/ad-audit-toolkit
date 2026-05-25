# Contributing Guide

Thank you for your interest in contributing! This project welcomes bug reports,
feature suggestions, documentation improvements, and pull requests.

## Getting Started

1. **Fork** the repository and clone your fork
2. Create a **feature branch**: `git checkout -b feat/your-feature-name`
3. Set up the development environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

## Code Standards

- **Style**: PEP 8, enforced by `flake8` (max line length: 100)
- **Type hints**: Required for all public functions
- **Docstrings**: Module-level and public function docstrings required
- **Tests**: All new functionality must include pytest unit tests (target ≥ 80% coverage)
- **Logging**: Use the `logging` module — no bare `print()` statements in production code

## Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): short description

Optional longer description explaining why, not what.
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `security`

Examples:
```
feat(classifier): add confidence score to classification output
fix(sla_monitor): correct P1 SLA resolution threshold from 4h to 2h
security(deps): update cryptography to 41.0.7
```

## Pull Request Process

1. Ensure CI passes (lint + tests)
2. Update `README.md` if your change affects usage or architecture
3. Add your change to `CHANGELOG.md` under `[Unreleased]`
4. Request review from a maintainer
5. Squash commits before merge if the PR history is noisy

## Security

Do not include credentials, API keys, or personal data in contributions.
See [SECURITY.md](SECURITY.md) for vulnerability reporting.
