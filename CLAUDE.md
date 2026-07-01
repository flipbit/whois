# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

.NET library for querying and parsing WHOIS domain registration data. Targets .NET Standard 2.0 and .NET Framework 4.5.2. Published as the `Whois` NuGet package.

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

# Build release (library only)
dotnet build src/Whois/Whois.csproj -c Release -f netstandard2.0
```

## Architecture

### Lookup Pipeline

`WhoisLookup` orchestrates the full query flow:

1. **Server Discovery** (`Servers/IanaServerLookup`) — queries `whois.iana.org` to find the authoritative WHOIS server for a TLD
2. **Download** (`Net/TcpReader` via `ITcpReader`) — connects to the WHOIS server over TCP port 43
3. **Parse** (`Parsers/WhoisParser`) — matches the raw text response against Tokenizer templates to produce a structured `WhoisResponse`
4. **Referrer Chain** — follows WHOIS referral servers (e.g., Verisign → registrar) until no further referrer is found or a loop is detected

### Template-Based Parsing

Parsing uses the external [Tokenizer](https://github.com/flipbit/tokenizer) library (`TokenMatcher`). Templates are embedded resources in `src/Whois/Resources/`, organized by WHOIS server hostname (e.g., `Resources/whois.nic.uk/uk/Found.txt`). The parser:

- First tries server-specific templates (tagged with the server hostname)
- Falls back to generic catch-all templates in `Resources/generic/tld/`
- Applies `IFixup` post-processing steps (e.g., `MultipleContactFixup`) after template matching

### Test Structure

- **Whois.Tests** — unit tests using NUnit + Moq. Parsing tests live in `tests/Whois.Tests/Parsing/` mirroring the server directory structure. Each test class extends `ParsingTests` and uses `SampleReader` to load sample WHOIS responses from `tests/Whois.Tests/Samples/` (also organized by server/TLD). Sample files in tests mirror the embedded resource structure in the main library.
- **Whois.Tests.Integration** — live network tests against real WHOIS servers

### Key Conventions

- WHOIS response templates use Tokenizer syntax (see `Resources/generic/tld/Found01.txt` for an example with directives like `name:`, `tag:`, `set:`, `outOfOrder:`)
- To add support for a new registrar: add a template `.txt` in `src/Whois/Resources/<server>/<tld>/`, add it as `EmbeddedResource` in `src/Whois/Whois.csproj`, add sample responses in `tests/Whois.Tests/Samples/<server>/<tld>/`, and write parsing tests
- Sync/async parity: all public methods have both sync (`Lookup`) and async (`LookupAsync`) variants; sync versions use `AsyncHelper.RunSync`
- Networking is abstracted via `ITcpReader` for testability
