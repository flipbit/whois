# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — v4.0.0

### Added
- `CancellationToken` support on all async methods
- `Microsoft.Extensions.Logging` integration (`ILogger<T>`)
- DI support via `AddWhois()` extension method on `IServiceCollection`
- Options pattern (`IOptions<WhoisOptions>`) with lambda configuration and `IConfiguration` binding
- Nullable reference type annotations across the public API
- `net8.0` and `net10.0` target frameworks
- GitHub Actions CI workflow
- Central Package Management (`Directory.Packages.props`)
- `.editorconfig` with project code style conventions

### Changed
- `TcpReader` is now stateless — no `IDisposable` needed
- `LookupAsync()` renamed to `Lookup()` — async-only, no `Async` suffix needed
- `WhoisOptions` now uses inline property defaults instead of a static `Defaults` object
- Test framework migrated from NUnit/Moq to xUnit/NSubstitute
- Console tool uses `System.Text.Json` instead of `Newtonsoft.Json`
- Timeout mechanism uses `CancellationTokenSource.CancelAfter` instead of `Task.WhenAny(Task.Delay)`
- Repository restructured to standard `src/tests/tools/docs` layout
- `ITcpReader.Read` signature now includes `CancellationToken` parameter

### Removed
- Sync `Lookup()` methods — use `await lookup.Lookup(...)` instead
- `AsyncHelper` class
- `IDisposable` from `IWhoisLookup`, `ITcpReader`, and `IWhoisServerLookup`
- `net452` target framework
- `LibLog` dependency — replaced with `Microsoft.Extensions.Logging`
- `Microsoft.CSharp` dependency
- `Newtonsoft.Json` from console app
- AppVeyor CI (`appveyor.yml`)
- `WhoisOptions.Defaults` static property — use `new WhoisOptions()` instead
- `WhoisOptions.Clone()` method

### Breaking Changes
- All public async methods renamed from `*Async()` to the base name (e.g. `LookupAsync` → `Lookup`)
- `ITcpReader.Read` signature changed — `CancellationToken` parameter added
- `WhoisOptions.Defaults` removed — use `new WhoisOptions()` for defaults
- `WhoisOptions.Clone()` removed
- `IWhoisLookup`, `ITcpReader`, and `IWhoisServerLookup` no longer implement `IDisposable`

---

## [3.x] — Historical

### Dependency Updates
- Bump `Serilog` from 2.11.0 to 2.12.0
- Bump `NUnit3TestAdapter` from 4.3.0 to 4.5.0
- Bump `Moq` from 4.18.2 to 4.18.4
- Bump `Microsoft.NET.Test.Sdk` from 17.2.0 to 17.6.2
- Bump `Newtonsoft.Json` from 13.0.1 to 13.0.3
- Bump `CommandLineParser` from 2.8.0 to 2.9.1
- Bump `Serilog.Sinks.Console` from 4.0.0 to 4.1.0

### Added
- GitHub Actions CodeQL workflow for code scanning
- Target framework updates to modern .NET

### Fixed
- `SampleReader` path separators for cross-platform CI compatibility
- Mojibake in test expectations — corrected Unicode encoding
- Template syntax errors in `.by` and `.gov` templates

---

## [Pre-3.x] — Legacy

- Upgrade to .NET Standard 2.0 (dropped .NET 3.5 / .NET 2.0 era code)
- Externalised Tokenizer as an independent library
- Added parsing support for many TLDs: `.pl`, `.cz`, `.be`, `.jp`, `.au`, `.ax`, `.br`, `.cc`, `.co.za`, `.durban`, `.joburg`, `.pe`, `.org.za`, `.tv`, `.ae`, `.info`, `.pro`, `.bz`, `.gi`, `.lc`, `.mn`, `.sc`, `.vc`, `.am`, `.tn`, `.bn`, `.capetown`, `.pt`
- Added IANA TLD lookup
- Added support for domain referral/redirect chains
- Added contact detail extraction
- Added character encoding support
- Initial open-source release

[Unreleased]: https://github.com/flipbit/whois/compare/HEAD...HEAD
