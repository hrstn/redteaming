# Contributing to mcpray

Thanks for your interest in improving mcpray. This guide covers everything you need to
get a development environment running and land a quality pull request.

## Getting Started

```bash
# 1. Fork and clone
git clone https://github.com/<your-username>/mcpray
cd mcpray

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install in editable mode with dev dependencies
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest tests/
```

All new code should be accompanied by tests. Pull requests that reduce coverage or break
existing tests will not be merged.

## Linting and Formatting

mcpray uses [ruff](https://docs.astral.sh/ruff/) for both linting and formatting:

```bash
ruff check .
ruff format .
```

Run both before pushing. CI enforces a clean ruff run.

## Commit Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/). Prefix each commit
message with one of:

| Type       | Use for                                            |
|------------|----------------------------------------------------|
| `feat`     | A new feature                                      |
| `fix`      | A bug fix                                           |
| `docs`     | Documentation-only changes                          |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `test`     | Adding or correcting tests                          |
| `chore`    | Build process, tooling, or dependency changes       |

Example: `feat(sqli): add Oracle dialect detection`

## Pull Request Process

1. **Fork** the repository.
2. Create a feature **branch** off `main` (e.g. `feat/oracle-dialect`).
3. Make your changes, with tests and a clean ruff run.
4. Update `CHANGELOG.md` under the `[Unreleased]` section.
5. Open a **PR against `main`** using the pull request template.
6. Address review feedback. A maintainer will merge once approved.

## Code Style

- ruff-enforced formatting and linting (see above).
- **Type annotations are required** for all public functions and methods.
- Match existing patterns and naming conventions in the codebase.
- Prefer simple, readable code over clever solutions.

## Adding a New Scanner

mcpray scanners live in `mcpray/scanners/`. To add one:

1. Create a new module following the existing scanner pattern (see an existing scanner such
   as `mcpray/scanners/sqli.py` for structure — a class that takes an `MCPClient` and
   produces `Finding` objects).
2. Wire it into the active scan integration in `mcpray/scanners/active.py` so it runs as
   part of `mcpray scan --active`.
3. Add tests under `tests/`.
4. Document the scanner and any new CLI command in `README.md`.
5. Note the change in `CHANGELOG.md`.

## Legal Reminder

By contributing, you agree your contributions comply with the project's authorized-use-only
scope (see [SECURITY.md](SECURITY.md)). **Contributions that add capabilities intended to
facilitate unauthorized access, evade legal authorization controls, or otherwise enable
illegal activity will not be accepted.**
