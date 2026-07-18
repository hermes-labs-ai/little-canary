# Contributing to Little Canary

Thank you for considering contributing to Little Canary. This document explains how to get started.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/hermes-labs-ai/little-canary.git
cd little-canary

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Optional live evaluation: install Ollama using its reviewed platform
# instructions, then use a dedicated runtime before pulling/calling a model.
# Model pulls and live prompts cause network or loopback egress.
```

## How to Contribute

### Reporting Bugs

Open a [bug report](https://github.com/hermes-labs-ai/little-canary/issues/new?template=bug_report.md) with:
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Python version, Ollama version, canary model)

### Suggesting Features

Open a [feature request](https://github.com/hermes-labs-ai/little-canary/issues/new?template=feature_request.md) describing the use case and proposed solution.

### Submitting Changes

1. Fork the repository
2. Create a feature branch from `main`: `git checkout -b feature/your-feature`
3. Make your changes
4. Run the offline suite and lint checks:
   ```bash
   pytest
   ruff check little_canary tests
   ```
   If detector behavior changes, also run the case-level benchmark controls on
   a dedicated model runtime after inspecting the runner's egress and output
   paths. Do not reduce the result to a rate without the evidence described in
   `benchmarks/README.md`.
5. Commit with a clear message describing what and why
6. Push to your fork and open a Pull Request

### Pull Request Guidelines

- Keep PRs focused on a single change
- Include a description of what changed and why
- If adding detection patterns, include example inputs that trigger them
- If changing scoring or mode logic, include before/after benchmark results
- Maintain the declared Python 3.9–3.12 support range

## Project Structure

- `little_canary/` — Core library. Changes here affect all users.
- `examples/` — Integration examples. Keep these simple and self-contained.
- `benchmarks/` — Historical harnesses and prompt datasets. Inspect egress and
  evidence limitations before running them after detection-logic changes.

## Code Style

- Use type hints on public method signatures
- Use dataclasses for data structures
- Follow existing patterns in the codebase
- Keep the single runtime dependency (`requests`) — do not add new dependencies to the core package without discussion

## Security Vulnerabilities

Do **not** open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
