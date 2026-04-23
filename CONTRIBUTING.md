# Contributing to Little Canary

Thank you for considering contributing to Little Canary. This document explains how to get started.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/hermes-labs-ai/little-canary.git
cd little-canary

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Install Ollama and pull the canary model
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:1.5b
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
4. Run the false positive test to verify you haven't introduced regressions:
   ```bash
   cd benchmarks && python3 run_fp_test.py
   ```
5. Commit with a clear message describing what and why
6. Push to your fork and open a Pull Request

### Pull Request Guidelines

- Keep PRs focused on a single change
- Include a description of what changed and why
- If adding detection patterns, include example inputs that trigger them
- If changing scoring or mode logic, include before/after benchmark results
- Maintain Python 3.8 compatibility (no walrus operator, no `match`, no `|` union types)

## Project Structure

- `little_canary/` — Core library. Changes here affect all users.
- `examples/` — Integration examples. Keep these simple and self-contained.
- `benchmarks/` — Test harnesses and prompt datasets. Run these after any detection logic change.

## Code Style

- Use type hints on public method signatures
- Use dataclasses for data structures
- Follow existing patterns in the codebase
- Keep the single runtime dependency (`requests`) — do not add new dependencies to the core package without discussion

## Security Vulnerabilities

Do **not** open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
