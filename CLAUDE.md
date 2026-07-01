# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

.NET library for querying and parsing WHOIS domain registration data. Targets `netstandard2.0`, `net8.0`, and `net10.0`. Published as the `Whois` NuGet package (v4.0.0).

## Build & Test Commands

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

- **Directory.Build.props** — shared build settings: `LangVersion=latest`, `Nullable=enable`, `ImplicitUsings=enable`, `TreatWarningsAsErrors=true`, `Deterministic=true`
- **Directory.Packages.props** — Central Package Management; all package versions are centralized here
- **GitHub Actions** (`.github/workflows/build.yml`) — CI runs build + test matrix across net8.0/net10.0 on ubuntu/windows

## Architecture

### Lookup Pipeline

`WhoisLookup` orchestrates the full query flow:

1. **Server Discovery** (`Servers/IanaServerLookup`) — queries `whois.iana.org` to find the authoritative WHOIS server for a TLD
2. **Download** (`Net/TcpReader` via `ITcpReader`) — connects to the WHOIS server over TCP port 43. `TcpReader` is stateless (creates a new `TcpClient` per call) and supports `CancellationToken` for timeouts via `CancellationTokenSource.CancelAfter`.
3. **Parse** (`Parsers/WhoisParser`) — matches the raw text response against Tokenizer templates to produce a structured `WhoisResponse`
4. **Referrer Chain** — follows WHOIS referral servers (e.g., Verisign → registrar) until no further referrer is found or a loop is detected

### API Design

- **Async-only** — all public methods return `Task<T>` and accept `CancellationToken cancellationToken = default`. No sync wrappers.
- **No `IDisposable`** — `IWhoisLookup`, `ITcpReader`, and `IWhoisServerLookup` are not disposable (TcpReader is stateless).
- **DI support** — `services.AddWhois()` registers all services. Accepts `Action<WhoisOptions>` or `IConfiguration` for configuration.
- **Logging** — uses `Microsoft.Extensions.Logging.Abstractions` (`ILogger<T>`). Defaults to `NullLogger` when constructed without DI.
- **Options pattern** — `WhoisOptions` works with `IOptions<WhoisOptions>` for DI or can be passed directly.

### netstandard2.0 Compatibility

`#if` conditional compilation is centralised in `src/Whois/Net/NetStandardShims.cs`. This is the only file with `#if` directives. It provides shims for `ConnectAsync(CancellationToken)` and `ReadLineAsync(CancellationToken)` which don't exist on netstandard2.0.

### Template-Based Parsing

Parsing uses the external [Tokenizer](https://github.com/flipbit/tokenizer) library (`TokenMatcher`). Templates are embedded resources in `src/Whois/Resources/` (included via glob: `Resources/**/*.txt`), organized by WHOIS server hostname (e.g., `Resources/whois.nic.uk/uk/Found.txt`). The parser:

- First tries server-specific templates (tagged with the server hostname)
- Falls back to generic catch-all templates in `Resources/generic/tld/`
- Applies `IFixup` post-processing steps (e.g., `MultipleContactFixup`) after template matching

### Test Structure

- **Whois.Tests** — unit tests using xUnit + NSubstitute. Parsing tests live in `tests/Whois.Tests/Parsing/` mirroring the server directory structure. Each test class extends `ParsingTests` and uses `SampleReader` to load sample WHOIS responses from `tests/Whois.Tests/Samples/` (also organized by server/TLD). Sample files in tests mirror the embedded resource structure in the main library.
- **Whois.Tests.Integration** — live network tests against real WHOIS servers (including ReadmeTests that demonstrate API usage)

### Key Conventions

- WHOIS response templates use Tokenizer syntax (see `Resources/generic/tld/Found01.txt` for an example with directives like `name:`, `tag:`, `set:`, `outOfOrder:`)
- To add support for a new registrar: add a template `.txt` in `src/Whois/Resources/<server>/<tld>/`, add sample responses in `tests/Whois.Tests/Samples/<server>/<tld>/`, and write parsing tests (embedded resources are included automatically via glob)
- Networking is abstracted via `ITcpReader` for testability
