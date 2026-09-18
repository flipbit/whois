# AGENTS.md

Instructions for AI agents working on this codebase.

## Project Overview

Whois is a .NET library for querying and parsing WHOIS and RDAP domain registration data. Published as the `Whois` NuGet package.

- **Targets**: .NET Standard 2.0, .NET 8.0, and .NET 10.0
- **Root namespace**: `Whois`
- **Language**: C# with `LangVersion=latest`, nullable reference types enabled

## Build Commands

```bash
# Restore and build
dotnet restore Whois.sln
dotnet build Whois.sln

# Run unit tests
dotnet test tests/Whois.Tests/Whois.Tests.csproj

# Run integration tests (requires network access to WHOIS servers)
dotnet test tests/Whois.Tests.Integration/Whois.Tests.Integration.csproj

# Run a single test by name
dotnet test tests/Whois.Tests/Whois.Tests.csproj --filter "FullyQualifiedName~TestClassName.TestMethodName"

# Build release and pack
dotnet build src/Whois/Whois.csproj -c Release
dotnet pack src/Whois/Whois.csproj -c Release --no-build
```

## Build Infrastructure

- **Directory.Build.props** - shared build settings: `LangVersion=latest`, `Nullable=enable`, `ImplicitUsings=enable`, `TreatWarningsAsErrors=true`, `Deterministic=true`
- **Directory.Packages.props** - Central Package Management; all package versions are centralised here
- **GitHub Actions** (`.github/workflows/build.yml`) - CI runs build + test matrix across net8.0/net10.0 on ubuntu/windows

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the lookup pipeline, API design, parsing engine, and test structure.

## Code Conventions

- WHOIS response templates use Tokenizer syntax (see `Resources/generic/tld/Found01.txt` for an example with directives like `name:`, `tag:`, `set:`, `outOfOrder:`)
- To add support for a new registrar: add a template `.txt` in `src/Whois/Resources/<server>/<tld>/`, add sample responses in `tests/Whois.Tests/Samples/<server>/<tld>/`, and write parsing tests (embedded resources are included automatically via glob)
- Networking is abstracted via `ITcpReader` for testability
- Conditional compilation is centralised in `src/Whois/Net/NetStandardShims.cs` - this is the only file with `#if` directives

## Code Style Enforcement

Style and quality rules are enforced via `.editorconfig` and Roslyn analyzers. `TreatWarningsAsErrors` + `EnforceCodeStyleInBuild` means violations break the build locally and in CI.

**Per-rule commands (useful for targeted fixes):**

```bash
# Check one rule (dry run)
dotnet format style ./Whois.sln --verify-no-changes --diagnostics IDE0005

# Auto-fix one rule
dotnet format style ./Whois.sln --diagnostics IDE0005
```

**Source of truth:** `.editorconfig` - all rules and severities are defined there.

## Testing Conventions

- **Framework**: xUnit with NSubstitute for mocks
- **Structure**: Parsing tests in `tests/Whois.Tests/Parsing/` mirror the server directory structure. Each test class extends `ParsingTests` and uses `SampleReader` to load sample WHOIS responses from `tests/Whois.Tests/Samples/`
- **Integration tests**: `tests/Whois.Tests.Integration/` - live network tests against real WHOIS servers. These require network access and will fail in offline environments.
