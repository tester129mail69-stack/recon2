# Contributing to GODRECON

Thank you for your interest in contributing to GODRECON! This guide will help you get started.

## Setting Up the Development Environment

1. **Clone the repository**:
   ```bash
   git clone https://github.com/tester129mail69-stack/recon2.git
   cd recon2
   ```

2. **Create a virtual environment**:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install in editable mode with dev dependencies**:
   ```bash
   pip install -e ".[dev]"
   ```

## Running Tests

```bash
pytest
```

To run tests with coverage:

```bash
pytest --cov=godrecon --cov-report=term-missing tests/
```

## Running Linting

```bash
ruff check .
```

To auto-fix lint issues:

```bash
ruff check --fix .
```

To check formatting:

```bash
ruff format --check .
```

To apply formatting:

```bash
ruff format .
```

## Code Style Guidelines

- Follow existing patterns and conventions in the codebase.
- Use type hints for all function signatures.
- Write docstrings for all public classes, methods, and functions.
- Keep line length at 120 characters or fewer.
- Use `from __future__ import annotations` in all Python files.

## Pull Request Guidelines

1. **Create a branch** off `main` with a descriptive name:
   ```bash
   git checkout -b feature/my-new-feature
   ```

2. **Write tests** for any new functionality. Aim for coverage of the happy path and common edge cases.

3. **Ensure CI passes** — all tests, linting, and formatting checks must pass before merging.

4. **Write a clear PR description** explaining what changed and why.

5. **Keep PRs focused** — one feature or fix per PR makes reviews easier.

## Finding Things to Work On

Check the [issues page](https://github.com/tester129mail69-stack/recon2/issues) for open bugs, feature requests, and enhancements tagged `good first issue` or `help wanted`.
