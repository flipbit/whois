# Contributing

## Getting Started

1. Fork the repository
2. Clone your fork
3. Create a feature branch from `main`

## Prerequisites

- [.NET SDK 10.0](https://dotnet.microsoft.com/download) or later (pinned in `global.json`)

## Building

```bash
dotnet build Whois.sln
```

## Testing

```bash
# Unit tests
dotnet test tests/Whois.Tests/Whois.Tests.csproj

# Integration tests (requires network access to WHOIS servers)
dotnet test tests/Whois.Tests.Integration/Whois.Tests.Integration.csproj
```

All pull requests need to pass the full test suite on both Ubuntu and Windows (CI enforces this).

## Code Style

Code style is enforced by `.editorconfig` and Roslyn analyzers, so the build will fail on violations. To check formatting:

```bash
dotnet format style ./Whois.sln --verify-no-changes
```

To auto-fix:

```bash
dotnet format style ./Whois.sln
```

## Pull Requests

- Keep changes focused. One logical change per PR.
- Add tests for new functionality and bug fixes.
- Update `CHANGELOG.md` under the `[Unreleased]` section.
- Make sure all tests pass and the build is clean before submitting.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for an overview of how the library is structured.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE.txt).
