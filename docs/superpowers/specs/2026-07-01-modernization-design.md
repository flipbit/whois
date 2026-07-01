# Whois Library v4.0 Modernization Design

_Spec for modernizing the Whois .NET library from 2018-era tooling to 2026 standards._

---

## Overview

Full modernization of the Whois library, published as a breaking v4.0 release. The work is sequenced into 5 phases, each independently reviewable and committable. Each phase changes one dimension at a time to minimize risk.

**Target frameworks (library):** `netstandard2.0;net8.0;net10.0`
**Target frameworks (tests):** `net8.0;net10.0`
**Target frameworks (console):** `net10.0`

---

## Phase 1: Build Foundation + TFM Updates + CI

Mechanical changes to get the repo building on modern TFMs with a proper CI pipeline.

### Target framework changes

| Project | Before | After |
|---|---|---|
| `Whois.csproj` | `netstandard2.0;net452` | `netstandard2.0;net8.0;net10.0` |
| `Whois.Tests.csproj` | `netcoreapp2.1` | `net8.0;net10.0` |
| `Whois.Tests.Integration.csproj` | `netcoreapp2.1` | `net8.0;net10.0` |
| `Whois.Console.csproj` | `netcoreapp2.1` | `net10.0` |

### Directory.Build.props (solution root)

Shared properties for all projects:
- `LangVersion=latest`
- `Nullable=enable`
- `ImplicitUsings=enable`
- `TreatWarningsAsErrors=true`
- `Deterministic=true`
- Shared package metadata (Authors, Copyright 2026)
- `<NoWarn>` to suppress nullable warnings initially (removed in Phase 3)

### Directory.Packages.props (Central Package Management)

All package versions centralized. Individual csproj `<PackageReference>` elements drop `Version=`.

### Whois.csproj cleanup

- Replace ~660 lines of `<None Remove>` + `<EmbeddedResource Include>` with `<EmbeddedResource Include="Resources/**/*.txt" />`
- Remove the `net452` conditional compilation block (`#if !NET452`)
- Update package metadata: Copyright, Description

### .editorconfig

Standard .NET analyzer ruleset matching existing code style (indentation, bracing conventions).

### CI/CD

- New `.github/workflows/build.yml`: `dotnet build` + `dotnet test`, matrix across `net8.0`/`net10.0` on ubuntu + windows
- Bump CodeQL workflow to `checkout@v4` + `codeql-action@v3`
- Delete `appveyor.yml`

### Outcome

Everything builds and tests pass on modern TFMs. Nullable is enabled but warnings are suppressed until Phase 3.

---

## Phase 2: Test Framework Migration

Mechanical migration of test infrastructure while the API surface is still stable. Done before API changes so we're not changing the test framework and the code under test simultaneously.

### NUnit to xUnit

- Replace `NUnit` + `NUnit3TestAdapter` with `xunit` + `xunit.runner.visualstudio`
- Attribute mappings:
  - `[TestFixture]` removed
  - `[Test]` to `[Fact]`
  - `[TestCase(...)]` to `[Theory]` + `[InlineData(...)]`
  - `[SetUp]` to constructor
  - `[TearDown]` to `IDisposable.Dispose()`
  - `[OneTimeSetUp]`/`[OneTimeTearDown]` to `IClassFixture<T>`
- Assertion mappings:
  - `Assert.AreEqual(expected, actual)` to `Assert.Equal(expected, actual)`
  - `Assert.IsNull` to `Assert.Null`
  - `Assert.IsNotNull` to `Assert.NotNull`
  - `Assert.IsTrue`/`IsFalse` to `Assert.True`/`Assert.False`
  - `Assert.That(x, Is.EqualTo(y))` to `Assert.Equal(y, x)`

### Moq to NSubstitute

- Replace `Moq` with `NSubstitute`
- Pattern mappings:
  - `new Mock<ITcpReader>()` to `Substitute.For<ITcpReader>()`
  - `mock.Setup(x => x.Method(...)).ReturnsAsync(result)` to `sub.Method(...).Returns(result)`
  - `mock.Object` to just the substitute directly
  - `mock.Verify(...)` to `sub.Received().Method(...)`

### Scope

Both `Whois.Tests` and `Whois.Tests.Integration` projects.

### Outcome

All tests pass on xUnit + NSubstitute. Test behavior is identical before and after.

---

## Phase 3: API Modernization

The main code change. Justifies the v4.0 major version bump.

### Async-only API

- Remove all sync `Lookup()` methods from `WhoisLookup`, `IWhoisLookup`, `IWhoisServerLookup`, `IanaServerLookup`
- Delete `AsyncHelper.cs` entirely
- Drop the `Async` suffix from all method names (no sync/async pairs means no need to disambiguate): `LookupAsync()` becomes `Lookup()`, `ReadAsync()` becomes `Read()` (noting that `ITcpReader.Read` is already named `Read`)

### CancellationToken support

Add `CancellationToken cancellationToken = default` to all async methods:
- `IWhoisLookup.Lookup()`
- `IWhoisServerLookup.Lookup()`
- `ITcpReader.Read()`

Wire cancellation into the referrer chain loop in `WhoisLookup`.

### TcpReader rewrite

- Make stateless: no shared `tcpClient`/`reader`/`writer` fields. Each `Read()` call creates and disposes its own `TcpClient` locally.
- Replace `Task.WhenAny(task, Task.Delay(timeout))` with `CancellationTokenSource.CreateLinkedTokenSource` + `CancelAfter`. No more leaked tasks/sockets.
- Remove `IDisposable` from `ITcpReader` (stateless means nothing to dispose).
- `WhoisLookup` and `IanaServerLookup` also drop `IDisposable` if TcpReader was their only disposable.

### Centralised #if helpers

Internal static class (e.g. `NetStandardShims`) wrapping the 2-3 places where `netstandard2.0` lacks an API:
- `ConnectAsync` with `CancellationToken`
- Any `ReadAsync(Memory<byte>, CancellationToken)` overloads

All `#if` directives are confined to this one file. No conditional compilation anywhere else in the codebase.

### Nullable annotations

- Remove the `<NoWarn>` suppression added in Phase 1
- Annotate the full public API surface: `WhoisResponse`, `WhoisRequest`, `Contact`, `Registrar`, `HostName`, etc.
- Work through internal code nullable warnings

### Outcome

Clean async-only API with cancellation support, no resource leaks, nullable-aware, with `netstandard2.0` compat isolated to one file.

---

## Phase 4: Dependencies + DI

### LibLog to Microsoft.Extensions.Logging

- Remove `LibLog` package reference
- Add `Microsoft.Extensions.Logging.Abstractions` (works on `netstandard2.0`)
- Replace `ILog Log = LogProvider.GetCurrentClassLogger()` with `ILogger<T>` injected via constructor
- Default to `NullLogger<T>.Instance` for callers who don't use logging (backward compat: `new WhoisLookup()` still works)

### Options pattern

- Rework `WhoisOptions` to be compatible with `Microsoft.Extensions.Options`
- Same properties (Encoding, TimeoutSeconds, FollowReferrer) structured for `IOptions<WhoisOptions>` binding
- `WhoisLookup` accepts `IOptions<WhoisOptions>` in constructor, or raw `WhoisOptions` for non-DI usage
- `WhoisRequest` can still override per-call settings

### DI extension (core package)

- `AddWhois(this IServiceCollection, Action<WhoisOptions>?)` extension method in the core `Whois` package
- Registers `IWhoisLookup` as transient (stateless after TcpReader rewrite), `IWhoisServerLookup` as transient, `ITcpReader` as transient (stateless, each call creates its own socket)
- Supports `IConfiguration` binding: `services.AddWhois(config.GetSection("Whois"))`
- Dependencies: `Microsoft.Extensions.DependencyInjection.Abstractions`, `Microsoft.Extensions.Options.ConfigurationExtensions`

### Microsoft.CSharp

- Investigate whether `dynamic` is actually used in the codebase
- Remove the `Microsoft.CSharp` dependency if unused

### Outcome

Standard .NET logging and configuration. Works with or without a DI container.

---

## Phase 5: Console App + Metadata + Docs

### Console app

- Replace `Newtonsoft.Json` with `System.Text.Json`
- Replace `Serilog` with `Microsoft.Extensions.Logging.Console`
- Remove broken `HintPath` reference if present
- Update to use async-only API

### Package metadata (Whois.csproj)

- `Copyright` updated to 2026
- `Description` updated to reflect current targets (remove ".NET Framework 4.5.2")
- Add `PackageReadmeFile` pointing to README.md
- `PackageLicenseExpression` (SPDX) instead of `PackageLicenseFile`

### Documentation

- Refresh `README.md`: updated targets, async-only API examples, `ILogger`/DI usage with `AddWhois()`, Options pattern configuration
- Add `CHANGELOG.md` backfilled from git history, with v4.0 breaking changes documented

### Outcome

Everything modernized, documented, and ready to ship as v4.0.

---

## Design Decisions Summary

| Decision | Choice | Rationale |
|---|---|---|
| Keep `netstandard2.0` | Yes | Small `#if` tax, avoids stranding .NET Framework users |
| `#if` strategy | Centralised shim class | Keeps conditional compilation out of business logic |
| Sync API | Remove (async-only) | Major version bump, no legitimate reason to block on TCP I/O |
| `Async` suffix | Drop | No sync/async pairs to disambiguate |
| Test framework | xUnit + NSubstitute | Modern defaults, Moq SponsorLink concerns |
| DI extension location | Core package | Small library, minimal dependency cost |
| Options pattern | `IOptions<WhoisOptions>` | Standard .NET configuration, supports lambda and appsettings.json |
| Logging | `ILogger<T>` via M.E.Logging | Industry standard, replaces deprecated LibLog |
| CI | GitHub Actions (build+test only) | Replace AppVeyor, no automated publishing yet |
| CHANGELOG | Backfilled from git history | Provides historical context alongside v4.0 changes |
