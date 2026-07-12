# WHOIS Pattern Refresh System — Continuation Prompt (Plans 3 & 4)

## How to Use This Prompt

Copy everything below the line into a new Claude Code conversation in the `/Users/work/Source/whois` working directory.

---

## Prompt

I'm continuing work on the WHOIS Pattern Refresh System. Plans 1 (Directory Migration) and 2 (Refresh Tool) are complete. I need to brainstorm, design, and implement Plans 3 and 4 in sequence.

### Project Overview

This is a .NET library (`Whois` NuGet package, v4.0.0-beta) for querying and parsing WHOIS domain registration data. Targets `netstandard2.0`, `net8.0`, `net10.0`. The project is at `/Users/work/Source/whois`.

The full design spec is at: `docs/superpowers/specs/2026-07-12-whois-pattern-refresh-design.md` — read this first for complete context.

### What's Already Done

**Branch:** `v4.0.0-beta.2` (25 commits ahead of `main`)

#### Plan 1: Directory Migration (Complete)

Templates and samples migrated to normalised `{server}/{tld}/{status}/` directory structure. Template front matter names updated. `SampleReader.Read()` takes 4 params. 781 tests were passing at end of Plan 1.

#### Plan 2: Refresh Tool (Complete)

**Tool:** `tools/WhoisRefresh/` — .NET console app with Spectre.Cli, added to `Whois.sln`.

**Commands:**
- `bootstrap` — generates `domains.jsonc` from parsing test files (extracts domains from `SampleReader.Read` + `DomainName.ToString()` assertions)
- `refresh` — queries live WHOIS servers, saves domain-named samples, writes `refresh-results.json`
- `detect` — compares against git-committed baseline, classifies drift (NoMatch, FieldRegression, TemplateShift, StatusMismatch), generates reports, creates/updates rolling PR via `gh` CLI

**Key architecture:**
- `DomainRegistry` loads/validates `domains.jsonc` (JSONC with comments, path traversal validation, duplicate domain detection, status key validation)
- `RefreshEngine` handles rate group parallelism (`Task.WhenAll` across groups, sequential within, configurable delay)
- `DriftClassifier` produces `List<DriftEntry>` with severity classification
- `DriftDetector` retrieves baseline via `git show HEAD:...` (not from working tree)
- `IDriftReporter` → `GhCliDriftReporter` handles branch management + PR creation/deduplication
- `IFileSystem` abstraction for testability
- `TypeRegistrar`/`TypeResolver` bridges Spectre.Cli to Microsoft.Extensions.DependencyInjection

**Test project:** `tests/WhoisRefresh.Tests/` — 43 tests passing

**Baseline state:**
- `tools/WhoisRefresh/domains.jsonc` — 189 servers, 576 domains, 66 marked `static: true`
- `tools/WhoisRefresh/refresh-results.json` — committed baseline (349 successful, 168 failed)
- Sample files now domain-named (e.g., `google.co.uk.txt` instead of `found.txt`)
- 513 parsing tests passing, 272 skipped with `[Fact(Skip = "Template update deferred - WHOIS response format changed")]` — templates need updating to match fresh WHOIS responses from live servers

**Dependencies added (in `Directory.Packages.props`):**
- `Spectre.Console` 0.50.0
- `Spectre.Console.Cli` 0.50.0

**Note:** `src/Whois/Whois.csproj` uses a ProjectReference to `~/Source/tokenizer/src/Tokenizer/Tokenizer.csproj` (sibling repo). Intentional during v4 beta development.

### Current Codebase Architecture

**Lookup Pipeline:** `WhoisLookup` orchestrates: server discovery (`IanaServerLookup`) → TCP download (`TcpReader`/`ITcpReader`) → parse (`WhoisParser`) → referral chain.

**Key classes for Plan 3:**

`WhoisLookup` (`src/Whois/WhoisLookup.cs`):
- Main entry point implementing `IWhoisLookup`
- Properties: `Parser` (WhoisParser), `TcpReader` (ITcpReader), `ServerLookup` (IWhoisServerLookup), `Options` (WhoisOptions)
- Logger via `ILogger<WhoisLookup>`
- Constructors: parameterless, `(WhoisOptions)`, `(IOptions<WhoisOptions>, ILogger)`, full DI `(IOptions<WhoisOptions>, ILogger, ITcpReader, IWhoisServerLookup)`
- `Lookup(domain)`, `Lookup(domain, encoding)`, `Lookup(request)` — all async with CancellationToken

`WhoisParser` (`src/Whois/Parsers/WhoisParser.cs`):
- Lazy-loads templates per server via `ResourceReader.GetNames(server)` + Tokenizer's `TemplateMatcher`
- `Templates` property (TemplateCollection), `FixUps` (IList<IFixup>)
- `Parse(string whoisServer, string content)` → WhoisResponse
- `LoadServerTemplates(server)` — checks `Templates.ContainsTag(server)`, loads from embedded resources if not already loaded
- `LoadServerGenericTemplates()` — catch-all templates tagged "catch-all"
- `AddTemplate(content, name)`, `ClearTemplates()` — for testing

`ResourceReader` (`src/Whois/ResourceReader.cs`):
- Reads embedded resources by prefix (`Whois.Resources.{server}.{tld}.`)
- `GetNames(server)` → List<string> (all templates for a server)
- `GetNames(server, tld)` → List<string>
- `GetContent(name)` → string
- Embedded resources included via glob: `<EmbeddedResource Include="Resources\**\*.txt" />`

`WhoisOptions` (`src/Whois/WhoisOptions.cs`):
- `Encoding` (default UTF8)
- `TimeoutSeconds` (default 10)
- `FollowReferrer` (default true)

`IWhoisLookup` (`src/Whois/IWhoisLookup.cs`):
- Interface: `Lookup(domain)`, `Lookup(domain, encoding)`, `Lookup(request)` — all return `Task<WhoisResponse>`

`WhoisServiceCollectionExtensions` (`src/Whois/WhoisServiceCollectionExtensions.cs`):
- `AddWhois(Action<WhoisOptions>?)` and `AddWhois(IConfiguration)` extension methods
- Registers ITcpReader→TcpReader, IWhoisServerLookup→IanaServerLookup, IWhoisLookup→WhoisLookup

**netstandard2.0 compatibility:** `#if` directives centralised in `src/Whois/Net/NetStandardShims.cs` only.

**Template system (Tokenizer v3 at ~/Source/tokenizer/src/Tokenizer):**
- `TemplateMatcher` — registers templates, `Tokenize(content, tags[])` → result with `BestMatch`
- `TemplateCollection` — `ContainsTag(tag)`, `Clear()`
- Templates have front matter with `name:`, `tag:`, `set:`, `hint:`, `outOfOrder:`
- Template `tag:` field is the server hostname (used for lazy-loading)

### What Needs To Be Done

#### Plan 3: Client-Side Template Updates

Modifications to the main Whois library (`src/Whois/`):

- **Template caching:** Check local cache for newer template pack before loading embedded resources (integrated with existing lazy-load-per-server in WhoisParser)
- **Auto-update (opt-in):** Async check on first lookup, exponential backoff (1h→4h→24h→7d), backoff state persisted in cache dir, corrupt state → reset to defaults
- **Manual update:** `WhoisLookup.UpdateTemplatesAsync(CancellationToken)` 
- **`WhoisLookup.TemplateStatus`** read-only property (CurrentVersion, Source, LastCheckTime, NextCheckTime, LastError, AutoUpdateEnabled)
- **Signature verification:** Ed25519 via minisign, public key compiled into NuGet, verify before extract, reject zip-slip/downgrade
- **HTTP hardening:** HTTPS-only, redirect limit 5, custom URL warning
- **Cache security:** Restrictive permissions, atomic writes, symlink detection, keep at most one cached pack
- **WhoisOptions additions:** `AutoUpdateTemplates`, `TemplateCacheDirectory`, `TemplateUpdateCheckInterval`, `TemplateReleaseUrl`
- **Structured logging** for all update operations (Warning/Info/Debug levels specified in spec)
- **Graceful degradation:** Never throw from update path, disable on disk failure for session lifetime

Spec sections: 5 (Signing), 6 (Client-Side Template Updates), 9 (Testing - Client-Side)

#### Plan 4: Release Pipeline & GitHub Actions

- **Template packaging:** Build .zip with `manifest.json` (CalVer version, content hashes, template list)
- **Signing:** minisign with Environment secret, detached .sig file
- **Changelog:** Generated from git diff between release tags, both JSON and markdown
- **Weekly refresh workflow** (`whois-refresh.yml`): Cron Sunday 02:00 UTC, workflow_dispatch, 30min timeout, scoped permissions, staleness alert (4 weeks), failure handling (partial success, all-fail)
- **Template release workflow** (`whois-template-release.yml`): Trigger on `Resources/**` push to main, protected environment, CalVer sequence from existing releases

Spec sections: 5 (Template Release Pipeline), 7 (GitHub Action Workflows), 9 (Testing - GitHub Actions)

### Key Architecture Details

**Tokenizer v3 (at ~/Source/tokenizer/src/Tokenizer):**
- Front matter settings: Culture, DefaultOffset, DefaultTimezone, OutOfOrderTokens, CaseSensitive, etc.
- DateTime improvements: timezone offset preservation, culture-aware parsing
- AST-based compilation, diagnostics, safety limits

**Build infrastructure:**
- `Directory.Build.props` — LangVersion=latest, Nullable=enable, ImplicitUsings=enable, TreatWarningsAsErrors=true, Deterministic=true
- `Directory.Packages.props` — Central Package Management
- GitHub Actions (`.github/workflows/build.yml`) — CI matrix net8.0/net10.0 on ubuntu/windows

### Process

For each plan:
1. Use the brainstorming skill to explore design decisions specific to that plan's scope
2. Write the implementation plan using the writing-plans skill  
3. Execute using subagent-driven-development
4. Move to the next plan

Start with Plan 3 (Client-Side Template Updates). Use the brainstorming skill first.
