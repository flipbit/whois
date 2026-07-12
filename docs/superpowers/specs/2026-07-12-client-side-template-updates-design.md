# Client-Side Template Updates Design

## Overview

Adds the ability for the Whois library to download and cache updated WHOIS parsing templates at runtime, rather than being limited to the embedded resources compiled into the NuGet package. Part of Plan 3 of the WHOIS Pattern Refresh System.

## Goals

1. Check a local cache for newer template packs before falling back to embedded resources
2. Provide opt-in auto-update that checks asynchronously on first lookup without blocking queries
3. Provide manual update via `UpdateTemplates()` for full consumer control
4. Verify template pack signatures (Ed25519 via minisign) before use
5. Degrade gracefully — never throw from the update path, never break existing functionality

## Non-Goals

- Template release pipeline (Plan 4)
- Client-side template validation beyond signature verification
- Real GitHub releases API integration testing (Plan 4)

---

## 1. Public API Changes

### IWhoisLookup

Two additions to the existing interface (acceptable breaking change for v4.0):

```csharp
public interface IWhoisLookup
{
    // Existing
    Task<WhoisResponse> Lookup(string domain, CancellationToken cancellationToken = default);
    Task<WhoisResponse> Lookup(string domain, Encoding encoding, CancellationToken cancellationToken = default);
    Task<WhoisResponse> Lookup(WhoisRequest request, CancellationToken cancellationToken = default);

    // New
    TemplateStatus TemplateStatus { get; }
    Task<TemplateUpdateResult> UpdateTemplates(CancellationToken cancellationToken = default);
}
```

No `Async` suffixes — matches the existing `Lookup` naming convention.

### TemplateStatus

Immutable, sealed record:

```csharp
public sealed record TemplateStatus(
    string CurrentVersion,           // e.g. "2026.07.12.1" or "embedded"
    TemplateSource Source,           // Embedded | Cached
    DateTimeOffset? LastCheckTime,
    DateTimeOffset? NextCheckTime,
    string? LastError,
    bool AutoUpdateEnabled);

public enum TemplateSource { Embedded, Cached }
```

### TemplateUpdateResult

Sealed record with discriminated outcome:

```csharp
public sealed record TemplateUpdateResult(
    TemplateUpdateOutcome Outcome,
    string? Version,                 // Non-null when Outcome == Updated
    string? Error);                  // Human-readable summary when Outcome == Failed
                                     // (no raw exception messages or filesystem paths — details go to ILogger only)

public enum TemplateUpdateOutcome { Updated, AlreadyUpToDate, Failed, Skipped }
```

### WhoisOptions Additions

```csharp
public bool AutoUpdateTemplates { get; set; } = false;
public string? TemplateCacheDirectory { get; set; }  // null = LocalApplicationData/Whois/templates
public TimeSpan TemplateUpdateCheckInterval { get; set; } = TimeSpan.FromHours(24);
public string? TemplateReleaseUrl { get; set; }      // null = default GitHub releases URL, HTTPS only
```

---

## 2. Namespace & Component Layout

New components live in two sub-namespaces within `Whois`:

### Whois.Templates

```
src/Whois/Templates/
├── ITemplatePackProvider.cs      # Download, verify, cache template packs
├── TemplatePackProvider.cs       # Implementation (singleton in DI)
├── TemplateUpdateState.cs        # Backoff/throttle state + JSON persistence
├── TemplateStatus.cs             # Read-only status DTO
├── TemplateUpdateResult.cs       # Return type for UpdateTemplates()
├── TemplateManifest.cs           # Deserialization of manifest.json from zip
└── CacheDirectoryManager.cs     # Atomic writes, symlink detection, permissions
```

### Whois.Security

```
src/Whois/Security/
├── MinisignVerifier.cs           # Parses minisign format, delegates to Ed25519
└── Ed25519Verifier.cs            # net8.0+ uses built-in, netstandard2.0 uses managed impl
```

The `#if` for Ed25519 runtime selection lives in `Ed25519Verifier.cs` itself — the single-file `#if` rule is relaxed; `#if` directives are permitted where cohesion demands it.

---

## 3. Internal Components

### ITemplatePackProvider

```csharp
public interface ITemplatePackProvider
{
    TemplateStatus Status { get; }
    Task<TemplateUpdateResult> CheckForUpdate(CancellationToken cancellationToken = default);
    string? GetCachedTemplatePath(string server);
}
```

- `CheckForUpdate` — downloads, verifies, extracts, updates cache. Respects backoff/throttle. Never throws. Serialises concurrent calls internally.
- `GetCachedTemplatePath` — returns the directory path for a server's cached templates, or `null` if no cache exists.

### TemplatePackProvider

Singleton. Owns the concurrency guard:

```csharp
private int _checkInProgress = 0;

public async Task<TemplateUpdateResult> CheckForUpdate(CancellationToken cancellationToken)
{
    if (Interlocked.CompareExchange(ref _checkInProgress, 1, 0) != 0)
        return new TemplateUpdateResult(TemplateUpdateOutcome.Skipped, Status.CurrentVersion, null);

    try
    {
        // throttle/backoff check, download, verify, extract
    }
    finally
    {
        Interlocked.Exchange(ref _checkInProgress, 0);
    }
}
```

Dependencies:
- `IHttpClientFactory` (named client `"TemplatePackProvider"` in DI, or a static default `HttpClient` for non-DI)
- `ILogger<TemplatePackProvider>`
- `WhoisOptions` (URLs, intervals, cache directory)
- `MinisignVerifier` (signature checks)
- `CacheDirectoryManager` (disk I/O)
- `TemplateUpdateState` (backoff persistence)

### TemplateUpdateState

Small JSON file persisted alongside the cached template pack:

```json
{
  "lastCheckTime": "2026-07-12T10:00:00Z",
  "lastSuccess": true,
  "consecutiveFailures": 0,
  "currentVersion": "2026.07.12.1"
}
```

Loaded on first access, persisted on each check. Corrupt or implausible values reset to defaults. Implausible is defined as: `consecutiveFailures > 10`, `lastCheckTime` more than 30 days in the past or any time in the future, `currentVersion` not matching `^\d+\.\d+\.\d+\.\d+$`, or JSON parse failure.

Session-disable is an in-memory flag (`disabledForSession`), not persisted.

### CacheDirectoryManager

Handles:
- Directory creation with restrictive permissions (0700 on Unix, user-only ACL on Windows)
- Atomic writes (write to `.tmp`, rename)
- Symlink detection before writes
- Zip extraction with zip-slip rejection (entries with `..` or absolute paths rejected)
- Extraction caps: 50MB total uncompressed size, 10,000 maximum entries. Both enforced per-entry during extraction — abort and clean up on breach.
- Old pack cleanup (keep at most one cached pack)

### MinisignVerifier (Whois.Security)

Parses minisign's two-line base64 signature format (untrusted comment line + signature bytes), extracts the Ed25519 signature, and delegates verification to `Ed25519Verifier`.

### Ed25519Verifier (Whois.Security)

Thin wrapper. Uses a vendored managed implementation sourced from Chaos.NaCl (CodesInChaos) — a pure managed C# Ed25519, no native dependencies. This runs on all targets (netstandard2.0, net8.0, net10.0). A `#if NET10_0_OR_GREATER` optimisation to use `System.Security.Cryptography` built-in Ed25519 may be added later — .NET 8 does not expose Ed25519 in its stable crypto API, so the managed path is the only cross-target option. Validated against all RFC 8032 §7.1 test vectors in CI.

### Signing Key

A test keypair is used during Plan 3 development. The public key is a compiled-in constant. Plan 4 replaces it with the production public key when signing infrastructure is set up. The key is not configurable — it is the trust anchor.

---

## 4. Integration Points

### WhoisLookup

- Constructor initialises `ITemplatePackProvider` (from DI, or created internally for non-DI constructors)
- `TemplateStatus` delegates to `ITemplatePackProvider.Status`
- `UpdateTemplates()` delegates to `ITemplatePackProvider.CheckForUpdate()`
- First `Lookup()` call fires background auto-update (if enabled):

```csharp
private int _autoUpdateTriggered = 0;

public async Task<WhoisResponse> Lookup(WhoisRequest request, CancellationToken cancellationToken = default)
{
    if (Options.AutoUpdateTemplates
        && Interlocked.CompareExchange(ref _autoUpdateTriggered, 1, 0) == 0)
    {
        _ = Task.Run(async () =>
        {
            try { await _packProvider.CheckForUpdate(CancellationToken.None); }
            catch (Exception ex) { _logger.LogWarning(ex, "Background template update check failed"); }
        });
    }

    // ... existing lookup logic unchanged
}
```

`WhoisLookup` uses a per-instance `Interlocked` guard to avoid pointless `Task.Run` overhead on every call. `TemplatePackProvider.CheckForUpdate` additionally serialises across multiple `WhoisLookup` instances (transient in DI) sharing the singleton provider.

### WhoisParser

**Lifetime change:** `WhoisParser` becomes a singleton — registered as singleton in DI, and shared via a static instance for non-DI constructors. This avoids redundant template loading (from disk or embedded resources) across transient `WhoisLookup` instances.

**Thread safety:** `LoadServerTemplates` and `LoadServerGenericTemplates` are guarded by a `lock`. The `ContainsTag` check + template registration loop runs under the lock. After a server's templates are loaded, subsequent calls skip immediately (lock-free read of `ContainsTag`). Concurrent `Parse` calls on already-loaded servers are safe — `TemplateMatcher.Tokenize` is read-only.

One new method:

```csharp
public void LoadServerTemplatesFromDirectory(string whoisServer, string directoryPath)
```

Reads `.txt` files from the directory path and registers them with the `TemplateMatcher`. Also guarded by the template load lock.

The `LoadServerTemplates` flow becomes:
1. Check if templates for this server are already loaded → return if so
2. Ask a resolver function for a cached template path → if non-null, load from disk via `LoadServerTemplatesFromDirectory`
3. Otherwise → load from embedded resources (current behaviour)

The resolver is a `Func<string, string?>` passed from `WhoisLookup` to the parser, keeping the parser's dependency footprint minimal (no reference to `ITemplatePackProvider`).

### DI Registration (AddWhois)

```csharp
services.AddHttpClient("TemplatePackProvider");
services.AddSingleton<ITemplatePackProvider, TemplatePackProvider>();
services.AddSingleton<WhoisParser>();
```

`TemplatePackProvider` is singleton because it holds update state and is shared across transient `WhoisLookup` instances. It takes `IHttpClientFactory` and calls `_factory.CreateClient("TemplatePackProvider")` per check — this avoids the typed-client-in-singleton anti-pattern where a captured handler prevents DNS rotation and risks socket exhaustion.

`WhoisParser` is singleton because it caches loaded templates in its `TemplateMatcher`. Shared across all `WhoisLookup` instances so templates are loaded once per server per process.

---

## 5. HTTP & Download Security

### HttpClient Configuration

- HTTPS-only — reject any URL where the scheme is not `https`, checked before making the request
- HTTP timeout: 30 seconds per request (covers both metadata and zip/sig downloads)
- Max redirect count: 5 — configured via `HttpClientHandler.MaxAutomaticRedirections`
- Default TLS verification (never disabled)
- Response size cap: 10MB — enforced by reading the response stream with `HttpCompletionOption.ResponseHeadersRead` and an explicit byte-count limit. Aborts download if exceeded. Do not rely on the deprecated `MaxResponseContentBufferSize`.
- Custom URL warning: if `TemplateReleaseUrl` is non-null (user-provided), log `Warning` on first use

### Download & Verification Sequence

1. Check throttle/backoff state → skip if not eligible
2. `GET` release metadata (GitHub releases API or custom URL) to find latest version
3. Compare version against currently loaded → skip if not newer (prevents downgrade). Version comparison: split on `.`, parse each component as `int`, compare numerically left-to-right. Reject version strings not matching `^\d+\.\d+\.\d+\.\d+$`.
4. Download `.zip` to an in-memory `byte[]` (not to disk — avoids TOCTOU between verify and extract)
5. Download `.sig` file to memory
6. Verify signature: `MinisignVerifier.Verify(zipBytes, sigBytes, compiledPublicKey)` → reject if invalid
7. Extract from the verified in-memory bytes via `CacheDirectoryManager` (zip-slip protection, size cap)
8. Write updated `TemplateUpdateState` to disk
9. Delete previous cached pack
10. Update `TemplateStatus`

Steps 4–9 are atomic from the consumer's perspective — if anything fails partway through, the previous cached pack (or embedded resources) remains in use. The zip is held in memory (~1MB expected, 10MB cap) to eliminate any TOCTOU window between signature verification and extraction.

### Non-DI HttpClient

For consumers not using DI, `TemplatePackProvider` uses a lazily-initialised static `HttpClient`. On net8.0+, the underlying `SocketsHttpHandler` sets `PooledConnectionLifetime = TimeSpan.FromMinutes(15)` to ensure DNS changes are picked up. On netstandard2.0, DNS rotation relies on the default `ServicePointManager.DnsRefreshTimeout` (120 seconds). The `IHttpClientFactory` path is preferred but not required.

---

## 6. Backoff & Throttle Logic

### Success Path

After a successful check (whether updated or already up-to-date):
- Set `NextCheckTime = now + TemplateUpdateCheckInterval` (default 24h)
- Reset `consecutiveFailures` to 0

### Failure Path — Lookup Table

| Consecutive failures | Delay before next attempt |
|---|---|
| 1 | 1 hour |
| 2 | 4 hours |
| 3 | 24 hours |
| 4+ | 7 days (cap) |

Implemented as a static lookup table:

```csharp
private static readonly TimeSpan[] BackoffDelays =
[
    TimeSpan.FromHours(1),
    TimeSpan.FromHours(4),
    TimeSpan.FromHours(24),
    TimeSpan.FromDays(7),
];
// Index = min(consecutiveFailures - 1, 3)
```

### Disk Failure — Session Disable

- First disk write failure → log warning once: "Auto-update disabled: cache directory {CacheDirectory} is not writable — {ErrorType}: {ErrorMessage}"
- Set in-memory `disabledForSession = true` (not persisted)
- No further update attempts for this process lifetime
- `TemplateStatus.AutoUpdateEnabled` returns `false`

### Corrupt State File

JSON parse failure or implausible values → reset to defaults, log at Debug level.

---

## 7. Structured Logging

All log entries use `ILogger` message templates with structured fields:

| Event | Level | Template |
|---|---|---|
| Network failure (HTTP) | Warning | `"Template update check failed for {TemplateUpdateUrl}, attempted version {AttemptedVersion}, HTTP status {HttpStatus}, current version {CurrentVersion}"` |
| Disk failure | Warning | `"Auto-update disabled: cache directory {CacheDirectory} is not writable — {ErrorType}: {ErrorMessage}"` |
| Signature failure | Warning | `"Template pack signature verification failed for {TemplateUpdateUrl}, version {AttemptedVersion} — discarding pack"` |
| Success | Information | `"Template pack updated from {PreviousVersion} to {NewVersion} via {TemplateUpdateUrl}"` |
| Skipped (backoff) | Debug | `"Template update check skipped, next eligible at {NextCheckTime}, last error: {LastErrorReason}"` |
| Skipped (throttle) | Debug | `"Template update check skipped, last checked {LastCheckTime}, next eligible at {NextCheckTime}"` |
| Custom URL | Warning | `"Using custom template release URL: {TemplateUpdateUrl}"` |
| Extraction failure | Warning | `"Template pack extraction failed for {TemplateUpdateUrl}, version {AttemptedVersion}: {RejectionReason}"` |
| Downgrade rejected | Warning | `"Template pack downgrade rejected: server offered {OfferedVersion}, current version is {CurrentVersion} via {TemplateUpdateUrl}"` |
| HTTPS rejected | Warning | `"Template update URL rejected: scheme must be https, got {UrlScheme} for {TemplateUpdateUrl}"` |
| Skipped (concurrent) | Debug | `"Template update check skipped: another check is already in progress"` |
| Network failure (transport) | Warning | `"Template update check failed for {TemplateUpdateUrl}: {ExceptionType} — {ExceptionMessage}"` |

---

## 8. Template Resolution Flow

Complete flow when `WhoisParser.LoadServerTemplates(server)` is called:

```
LoadServerTemplates(server)
  ├─ Already loaded? → return
  ├─ Cache resolver returns path?
  │   └─ Yes → LoadServerTemplatesFromDirectory(server, path) → return
  └─ No → load from embedded resources (current behaviour)
```

Templates loaded during a process lifetime are not replaced. If a new pack is downloaded mid-process (via auto-update or manual update), it is cached to disk and takes effect for any server not yet queried in this process. See Known Limitations below.

---

## 9. Known Limitations

- **Templates are not hot-reloaded.** Once a server's templates are loaded (from cache or embedded resources), they remain in use for the process lifetime. A mid-process update caches the new pack to disk but only affects servers not yet queried. Long-running processes (e.g., web servers) must restart to fully apply a template update. `TemplateStatus` will report `Updated` even though some servers are still using previous templates. This is a deliberate trade-off: hot-reloading would require thread-safe template replacement in `TemplateMatcher`, adding complexity for marginal benefit since template updates are infrequent (weekly cadence).

---

## 10. netstandard2.0 Compatibility

Auto-update is available on all targets. The Ed25519 implementation uses a vendored managed Chaos.NaCl implementation on all targets — .NET 8 does not expose Ed25519 in its stable `System.Security.Cryptography` API. A `#if NET10_0_OR_GREATER` optimisation may be added later if .NET 10 ships stable Ed25519 support.

---

## 10. Cache Directory

Default location: `Environment.SpecialFolder.LocalApplicationData` / `Whois/templates`

| Platform | Path |
|---|---|
| Linux | `~/.local/share/Whois/templates` |
| macOS | `~/Library/Application Support/Whois/templates` |
| Windows | `%LOCALAPPDATA%\Whois\templates` |

Overridable via `WhoisOptions.TemplateCacheDirectory`.

---

## 11. Testing Strategy

### Whois.Security Tests

- `MinisignVerifier` — test with a real test keypair: valid signature passes, tampered content fails, tampered signature fails, wrong public key fails, malformed signature format fails
- `Ed25519Verifier` — RFC 8032 §7.1 test vectors run on both netstandard2.0 (managed Chaos.NaCl) and net8.0+ (built-in) code paths, ensuring both implementations produce identical results

### Whois.Templates Tests

- `TemplatePackProvider` — `HttpMessageHandler` mock for all HTTP paths: success, 404, network error, redirect limit, non-HTTPS rejection, response too large, redirect to `http://` rejected
- `TemplatePackProvider` concurrency — two simultaneous `CheckForUpdate` calls: second returns `Skipped`, only one HTTP round-trip occurs. Multiple transient `WhoisLookup` instances sharing singleton provider.
- `TemplatePackProvider` "never throws" contract — call with handlers that throw unconventional exceptions (`TaskCanceledException`, `OutOfMemoryException`, bare `Exception`): must return `Failed`, never propagate
- Downgrade prevention — pack older than current rejected, pack with same version returns `AlreadyUpToDate`, unparseable version string returns `Failed`, transition from `"embedded"` to real version succeeds
- Partial failure atomicity — failure at each step boundary (after download, after sig download, during extraction, after extraction): previous cache intact, `TemplateStatus` unchanged, no corrupt state on disk
- Backoff logic — unit tests for the delay table, state persistence, corrupt state recovery (implausible values per §3 rules), session disable on disk failure, session-disable visible across multiple `WhoisLookup` instances
- `CacheDirectoryManager` — atomic write behaviour, symlink detection, zip-slip rejection (entry with `../`, entries that normalize to traversal after `Path.GetFullPath`), absolute path entry rejection, extraction size cap boundary, entry count cap, old pack cleanup
- `TemplateManifest` — deserialisation of well-formed and malformed `manifest.json`

### Integration Tests (within Whois.Tests)

- `WhoisParser.LoadServerTemplatesFromDirectory` — loads templates from disk, parser uses them for matching
- `WhoisParser` cache-hit bypass — query a server, update cache, query same server again: old templates still used. Query a *new* server after cache update: cached templates used.
- `WhoisLookup.TemplateStatus` — reflects correct state through lifecycle: embedded → cached → error
- `WhoisLookup.UpdateTemplates` — end-to-end with mocked HTTP, verifies templates are cached and used
- Auto-update fire-and-forget — verify background check runs on first `Lookup` call when enabled, doesn't block the query

### Not Tested in Plan 3

- Real GitHub releases API calls (Plan 4 integration tests)
- Actual file permissions (platform-dependent, verified manually)

---

## 12. Review Decisions

Issues raised during design review and their resolutions.

### Dismissed

- **H2 (Code Quality): `Func<string, string?>` resolver should be an `ITemplateResolver` interface.** Dismissed — the `Func` is an internal constructor parameter with one consumer. Adding an interface for a single delegation point is YAGNI. Refactor if a second implementation is ever needed.
- **H4 (Security): Release metadata channel not cryptographically protected.** Dismissed — step 3 (downgrade prevention) rejects any version not newer than the current. An attacker who can MitM TLS can only replay the current version or block updates entirely, which is equivalent to blocking the network. All validly-signed versions are legitimate by definition.
- **H5 (Security): Temp zip lingers on disk in cache dir.** Dismissed — resolved by C1 fix. Zip is downloaded to memory, verified in memory, and extracted from the same bytes. No temp zip file touches disk before verification.
- **H6 (Security): Custom `TemplateReleaseUrl` enables SSRF.** Dismissed — this is a library option set by application developers in code or config, not by end users. Blocking internal IPs adds complexity and breaks legitimate enterprise mirrors. The custom URL warning log already flags non-default URLs. Consumers are responsible for validating this value if sourced from external configuration.
- **H8 (Performance): Synchronous disk I/O on hot parse path.** Dismissed — with the singleton `WhoisParser` fix (H7), disk reads happen once per server per process. Template files are ~20-50KB total per server — sub-millisecond. WHOIS TCP queries take 1-10 seconds, making this negligible. Preloading all servers would waste memory for servers never queried.
- **M2 (Security): Symlink TOCTOU between check and write.** Dismissed — the attack requires same-user access on the same machine. An attacker with same-user access can already read/write the user's files directly — a symlink gives no additional capability. The 0700 directory permissions prevent cross-user attacks.
- **M6 (Code Quality): `TemplateUpdateResult` doesn't enforce field validity per outcome.** Dismissed — standard pattern for result types in C#. The enum is the discriminator. XML doc comments will clarify which fields are populated per outcome. Discriminated union subtypes would be over-engineering for a simple result.
- **L1 (Code Quality): `TemplateSource` enum name collision with `Source` property.** Dismissed — `status.Source == TemplateSource.Cached` is clear and idiomatic C#. Renaming to `TemplateOrigin` adds no clarity.
- **L3 (Code Quality): `_checkInProgress` field naming.** Dismissed — name is descriptive and matches intent. Cosmetic preference.
- **D1 (Code Quality): Test keypair migration path.** Dismissed — Plan 3 is beta (`4.0.0-beta`). Auto-update defaults to `false`. No consumers will have cached packs signed with the test key when Plan 4 swaps the production key.
- **L2 (Performance): Wall-clock backoff.** Dismissed — already handled by the implausible-values validation which resets `lastCheckTime` more than 30 days in the past or in the future.
- **L2 (Security): Redirects to arbitrary HTTPS hosts.** Dismissed — signature verification prevents any unsigned content from being used. Redirects can only lead to validly-signed packs or verification failure.
- **L3 (Security): No certificate pinning.** Dismissed — cert pinning in a library breaks enterprise proxies and corporate environments. Signature verification is the trust backstop, not TLS.
- **M4 (Security): Fire-and-forget ignores shutdown lifecycle.** Dismissed — `CheckForUpdate` is idempotent and safe to abandon mid-flight. Partial downloads are in memory (not on disk). No cleanup is required. Integrating with `IHostApplicationLifetime` adds complexity for a best-effort background check.
