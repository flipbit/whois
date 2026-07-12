# Client-Side Template Updates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the ability for the Whois library to download, verify, cache, and use updated WHOIS parsing templates at runtime.

**Architecture:** New components in `Whois.Security` (Ed25519/minisign verification) and `Whois.Templates` (download, cache, backoff). `WhoisParser` becomes singleton with lock-guarded template loading. `WhoisLookup` orchestrates — delegates to singleton `ITemplatePackProvider` for update checks. Templates loaded from disk cache take priority over embedded resources.

**Tech Stack:** .NET (netstandard2.0, net8.0, net10.0), xUnit, NSubstitute, `System.Security.Cryptography` (net8.0+), vendored Chaos.NaCl Ed25519 (netstandard2.0)

## Global Constraints

- Targets: `netstandard2.0`, `net8.0`, `net10.0`
- `#if` directives permitted in `Ed25519Verifier.cs` and `NetStandardShims.cs` only
- `TreatWarningsAsErrors=true`, `Nullable=enable`, `ImplicitUsings=enable`
- No `Async` suffixes on public methods (matches existing `Lookup` convention)
- All new public types are `sealed` where applicable
- Never throw from the update path — all failures return `TemplateUpdateResult` with `Failed` or `Skipped`
- Test output must be pristine — no unvalidated error output
- Spec: `docs/superpowers/specs/2026-07-12-client-side-template-updates-design.md`

---

### Task 1: Ed25519 Verification (Whois.Security)

**Files:**
- Create: `src/Whois/Security/Ed25519Verifier.cs`
- Create: `tests/Whois.Tests/Security/Ed25519VerifierTests.cs`

**Interfaces:**
- Consumes: nothing
- Produces: `Ed25519Verifier.Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature) → bool`

This is the lowest-level crypto primitive. On net8.0+ it delegates to `System.Security.Cryptography.Ed25519`. On netstandard2.0 it uses a vendored managed implementation from Chaos.NaCl.

**Implementation notes:**
- The `#if` dispatch lives in this file: `#if NETSTANDARD2_0` uses the managed path, `#else` uses `System.Security.Cryptography`
- For the managed netstandard2.0 path, vendor the Ed25519 verification-only code from Chaos.NaCl (CodesInChaos). This is ~3 files: `Ed25519.cs`, `Sha512.cs`, and supporting field arithmetic. Place in `src/Whois/Security/Internal/` as `internal` classes. Only verification is needed — no signing code.
- The `Ed25519Verifier` class itself is `internal static` — only consumed by `MinisignVerifier`

**Test approach:**
- Use the 7 test vectors from RFC 8032 §7.1 (Ed25519)
- Each vector has: secret key, public key, message, signature
- Verify that `Ed25519Verifier.Verify` returns `true` for valid vectors and `false` for tampered signatures
- Tests run on both net8.0 and net10.0 TFMs — the netstandard2.0 managed path is exercised when the test project targets a runtime that doesn't have built-in Ed25519 (but since tests target net8.0+, we need a separate approach to verify the managed path)
- Add an explicit test that calls the managed implementation directly (bypassing the `#if`) to ensure both paths are validated in CI

- [ ] **Step 1:** Write the RFC 8032 test vectors as a static test data class
- [ ] **Step 2:** Write failing tests — `Verify_WithRfc8032Vector_ReturnsTrue` (parameterised over all 7 vectors), `Verify_WithTamperedSignature_ReturnsFalse`, `Verify_WithWrongPublicKey_ReturnsFalse`
- [ ] **Step 3:** Run tests, verify they fail with "Ed25519Verifier does not exist"
- [ ] **Step 4:** Vendor the Chaos.NaCl Ed25519 verification code into `src/Whois/Security/Internal/`
- [ ] **Step 5:** Implement `Ed25519Verifier` with `#if` dispatch
- [ ] **Step 6:** Run tests, verify all pass
- [ ] **Step 7:** Add tests that explicitly call the managed implementation to validate it independently of `#if`
- [ ] **Step 8:** Run full test suite (`dotnet test tests/Whois.Tests/Whois.Tests.csproj`), verify no regressions
- [ ] **Step 9:** Commit

---

### Task 2: Minisign Signature Verification (Whois.Security)

**Files:**
- Create: `src/Whois/Security/MinisignVerifier.cs`
- Create: `tests/Whois.Tests/Security/MinisignVerifierTests.cs`

**Interfaces:**
- Consumes: `Ed25519Verifier.Verify(publicKey, message, signature)` from Task 1
- Produces: `MinisignVerifier.Verify(byte[] content, string signature, string publicKey) → bool`

Minisign format reference:
- **Public key:** base64-encoded, 42 bytes: 2-byte algorithm (`Ed`), 8-byte key ID, 32-byte public key
- **Signature file:** two lines: `untrusted comment: ...` (ignored), base64-encoded signature: 2-byte algorithm (`Ed`), 8-byte key ID, 64-byte Ed25519 signature
- Verification: Ed25519 verify the content bytes against the 64-byte signature using the 32-byte public key
- Key ID in signature must match key ID in public key

**Test approach:**
- Generate a real minisign test keypair using the `minisign` CLI tool (or hardcode a known test keypair). The test public key constant will later be compiled into the library.
- Sign a test payload, use that as the "valid" test fixture
- Tests: valid signature passes, tampered content fails, tampered signature fails, wrong public key fails, malformed signature format (not base64, wrong line count, wrong algorithm) fails, key ID mismatch fails

- [ ] **Step 1:** Generate a test minisign keypair. Record the public key string and store as a constant. Sign a test payload "Hello, World!" and record the signature string.
- [ ] **Step 2:** Write failing tests for all cases listed above
- [ ] **Step 3:** Run tests, verify they fail
- [ ] **Step 4:** Implement `MinisignVerifier` — parse public key, parse signature, extract Ed25519 components, delegate to `Ed25519Verifier`
- [ ] **Step 5:** Run tests, verify all pass
- [ ] **Step 6:** Run full test suite, verify no regressions
- [ ] **Step 7:** Commit

---

### Task 3: Public API Types (Whois.Templates)

**Files:**
- Create: `src/Whois/Templates/TemplateStatus.cs`
- Create: `src/Whois/Templates/TemplateUpdateResult.cs`
- Create: `src/Whois/Templates/TemplateManifest.cs`
- Create: `src/Whois/Templates/TemplateVersion.cs`
- Modify: `src/Whois/WhoisOptions.cs`
- Modify: `src/Whois/IWhoisLookup.cs`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `TemplateStatus` sealed record: `(string CurrentVersion, TemplateSource Source, DateTimeOffset? LastCheckTime, DateTimeOffset? NextCheckTime, string? LastError, bool AutoUpdateEnabled)`
  - `TemplateSource` enum: `Embedded, Cached`
  - `TemplateUpdateResult` sealed record: `(TemplateUpdateOutcome Outcome, string? Version, string? Error)`
  - `TemplateUpdateOutcome` enum: `Updated, AlreadyUpToDate, Failed, Skipped`
  - `TemplateManifest` class: `Version` (string), `ContentHash` (string), `TemplateCount` (int), `Templates` (list of per-template entries)
  - `TemplateVersion` static class: `TryParse(string, out int[]) → bool`, `Compare(int[], int[]) → int`, version regex `^\d+\.\d+\.\d+\.\d+$`
  - `WhoisOptions` additions: `AutoUpdateTemplates`, `TemplateCacheDirectory`, `TemplateUpdateCheckInterval`, `TemplateReleaseUrl`
  - `IWhoisLookup` additions: `TemplateStatus` property, `UpdateTemplates` method

These are pure data types with no behaviour beyond version parsing. No tests needed for the records/enums themselves. `TemplateVersion` and `TemplateManifest` need tests.

- [ ] **Step 1:** Write tests for `TemplateVersion`: `TryParse` with valid version `"2026.07.12.1"`, invalid `"abc"`, missing component `"2026.07"`, `Compare` returns positive/negative/zero for different versions, non-zero-padded `"2026.7.1.1"` parses correctly
- [ ] **Step 2:** Write tests for `TemplateManifest`: deserialise well-formed JSON, reject malformed JSON (missing fields, wrong types), reject manifest with invalid version string
- [ ] **Step 3:** Run tests, verify they fail
- [ ] **Step 4:** Create `TemplateVersion` with `TryParse` and `Compare`
- [ ] **Step 5:** Create `TemplateManifest` with JSON deserialization
- [ ] **Step 6:** Create `TemplateStatus`, `TemplateUpdateResult`, enums (pure types, no logic)
- [ ] **Step 7:** Add the four new properties to `WhoisOptions`
- [ ] **Step 8:** Add `TemplateStatus` and `UpdateTemplates` to `IWhoisLookup`
- [ ] **Step 9:** Add stub implementations to `WhoisLookup` so the project compiles (return `TemplateStatus` with `"embedded"`, return `TemplateUpdateResult` with `Failed`). These will be replaced in Task 7.
- [ ] **Step 10:** Run tests, verify new tests pass and no regressions
- [ ] **Step 11:** Commit

---

### Task 4: Cache Directory Manager (Whois.Templates)

**Files:**
- Create: `src/Whois/Templates/CacheDirectoryManager.cs`
- Create: `tests/Whois.Tests/Templates/CacheDirectoryManagerTests.cs`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `CacheDirectoryManager(string cacheDirectory, ILogger<CacheDirectoryManager> logger)`
  - `EnsureDirectory() → bool` — creates dir with restrictive perms, returns false on failure
  - `ExtractPack(byte[] zipBytes, string targetSubDirectory) → bool` — extracts verified zip, returns false on failure. Enforces: zip-slip rejection, 50MB uncompressed cap, 10,000 entry cap. Uses `Path.GetFullPath` normalisation for traversal detection.
  - `DeleteDirectory(string subDirectory) → bool` — removes old pack
  - `WriteFile(string relativePath, byte[] content) → bool` — atomic write (`.tmp` + rename)
  - `ReadFile(string relativePath) → byte[]?` — returns null if not found
  - `IsSymlink(string path) → bool`
  - `GetServerDirectory(string server) → string?` — returns full path to server's template dir within the cached pack, or null if not present

**Test approach:** All tests use a real temp directory (`Path.GetTempPath()` + unique subfolder), cleaned up in `Dispose`. No file system mocking — test the real filesystem operations.

- [ ] **Step 1:** Write tests: `EnsureDirectory_CreatesDirectory`, `EnsureDirectory_ReturnsFalseOnInvalidPath`
- [ ] **Step 2:** Write tests: `ExtractPack_ValidZip_ExtractsFiles`, `ExtractPack_ZipSlipEntry_Rejects` (entry with `../`), `ExtractPack_NormalisedTraversal_Rejects` (entry like `foo/../../bar`), `ExtractPack_AbsolutePath_Rejects`, `ExtractPack_ExceedsSizeCap_Rejects`, `ExtractPack_ExceedsEntryCap_Rejects`, `ExtractPack_CleansUpOnFailure`
- [ ] **Step 3:** Write tests: `WriteFile_AtomicWrite_Succeeds`, `ReadFile_ReturnsContent`, `ReadFile_MissingFile_ReturnsNull`, `DeleteDirectory_RemovesDir`, `GetServerDirectory_ReturnsPathWhenExists`, `GetServerDirectory_ReturnsNullWhenMissing`
- [ ] **Step 4:** Run tests, verify they all fail
- [ ] **Step 5:** Implement `CacheDirectoryManager` — directory creation, symlink detection, atomic writes
- [ ] **Step 6:** Implement `ExtractPack` — `ZipArchive` extraction with per-entry validation (path check via `Path.GetFullPath`, cumulative size tracking, entry count tracking)
- [ ] **Step 7:** Run tests, verify all pass
- [ ] **Step 8:** Run full test suite, verify no regressions
- [ ] **Step 9:** Commit

---

### Task 5: Template Update State (Whois.Templates)

**Files:**
- Create: `src/Whois/Templates/TemplateUpdateState.cs`
- Create: `tests/Whois.Tests/Templates/TemplateUpdateStateTests.cs`

**Interfaces:**
- Consumes: `CacheDirectoryManager.WriteFile`, `CacheDirectoryManager.ReadFile` from Task 4
- Produces:
  - `TemplateUpdateState(CacheDirectoryManager cache, ILogger<TemplateUpdateState> logger)`
  - `LastCheckTime` (DateTimeOffset?), `LastSuccess` (bool), `ConsecutiveFailures` (int), `CurrentVersion` (string?), `DisabledForSession` (bool — in-memory only)
  - `Load()` — reads state from disk, validates, resets implausible values
  - `Save()` — persists to disk via `CacheDirectoryManager`
  - `RecordSuccess(string version, DateTimeOffset checkTime)` — resets failures, updates version
  - `RecordFailure(DateTimeOffset checkTime)` — increments failures
  - `GetNextEligibleTime(TimeSpan checkInterval) → DateTimeOffset?` — computes next check time using backoff table or success interval
  - `IsEligibleForCheck(TimeSpan checkInterval) → bool`
  - `static BackoffDelays` — the `[1h, 4h, 24h, 7d]` lookup table

**Implausible values (reset to defaults):** `ConsecutiveFailures > 10`, `LastCheckTime` more than 30 days in the past or in the future, `CurrentVersion` not matching `^\d+\.\d+\.\d+\.\d+$`, JSON parse failure.

- [ ] **Step 1:** Write tests for backoff delay calculation: `GetNextEligibleTime` returns correct delay for 1, 2, 3, 4+ consecutive failures. Success path returns `now + checkInterval`.
- [ ] **Step 2:** Write tests for state persistence: `Save` then `Load` round-trips correctly. `Load` with missing file returns defaults. `Load` with corrupt JSON resets to defaults. `Load` with implausible values (future date, negative failures, failures > 10, bad version string) resets each individually.
- [ ] **Step 3:** Write tests: `RecordSuccess` resets failures and updates version. `RecordFailure` increments count. `IsEligibleForCheck` returns correct boolean based on timing. `DisabledForSession` prevents eligibility.
- [ ] **Step 4:** Run tests, verify they fail
- [ ] **Step 5:** Implement `TemplateUpdateState`
- [ ] **Step 6:** Run tests, verify all pass
- [ ] **Step 7:** Run full test suite, verify no regressions
- [ ] **Step 8:** Commit

---

### Task 6: WhoisParser Singleton + Cache Resolver

**Files:**
- Modify: `src/Whois/Parsers/WhoisParser.cs`
- Create: `tests/Whois.Tests/Parsers/WhoisParserCacheTests.cs`

**Interfaces:**
- Consumes: `CacheDirectoryManager.GetServerDirectory` from Task 4 (via `Func<string, string?>` resolver)
- Produces:
  - `WhoisParser(Func<string, string?>? cacheResolver = null)` — new constructor parameter
  - `LoadServerTemplatesFromDirectory(string whoisServer, string directoryPath)` — new public method
  - Thread-safe `LoadServerTemplates` and `LoadServerGenericTemplates` (lock-guarded)

**What changes in `WhoisParser`:**
1. Add `private readonly object _loadLock = new()` field
2. Add `private readonly Func<string, string?>? _cacheResolver` field
3. New constructor: `WhoisParser(Func<string, string?>? cacheResolver = null)` — parameterless constructor chains to this with `null`
4. `LoadServerTemplates`: wrap in `lock (_loadLock)`, add cache resolver check before embedded resource fallback
5. `LoadServerGenericTemplates`: wrap in `lock (_loadLock)`
6. New `LoadServerTemplatesFromDirectory`: reads `.txt` files from disk, registers with `_matcher`

**Test approach:** Create a temp directory with a few `.txt` template files (use existing template format from `src/Whois/Resources/`). Verify parser loads from disk when resolver returns a path, falls back to embedded when resolver returns null, and doesn't re-load already-loaded servers.

- [ ] **Step 1:** Write test `LoadServerTemplatesFromDirectory_LoadsTemplatesFromDisk` — create temp dir with a template file, call the method, verify `Templates.ContainsTag(server)` is true
- [ ] **Step 2:** Write test `LoadServerTemplates_WithCacheResolver_UsesCache` — resolver returns a path, verify templates loaded from disk not embedded resources
- [ ] **Step 3:** Write test `LoadServerTemplates_WithNullResolver_UsesEmbeddedResources` — verify existing behaviour unchanged
- [ ] **Step 4:** Write test `LoadServerTemplates_AlreadyLoaded_DoesNotReload` — load templates, modify resolver to return different path, call again, verify original templates still used
- [ ] **Step 5:** Write test `Parse_ConcurrentCalls_ThreadSafe` — call `Parse` from multiple threads simultaneously for different servers, verify no exceptions
- [ ] **Step 6:** Run tests, verify they fail
- [ ] **Step 7:** Implement the changes to `WhoisParser`
- [ ] **Step 8:** Run tests, verify all pass
- [ ] **Step 9:** Run full test suite (`dotnet test tests/Whois.Tests/Whois.Tests.csproj`), verify no regressions — this is critical as the parser is used by all 696+ existing passing tests
- [ ] **Step 10:** Commit

---

### Task 7: Template Pack Provider (Whois.Templates)

**Files:**
- Create: `src/Whois/Templates/ITemplatePackProvider.cs`
- Create: `src/Whois/Templates/TemplatePackProvider.cs`
- Create: `tests/Whois.Tests/Templates/TemplatePackProviderTests.cs`

**Interfaces:**
- Consumes:
  - `MinisignVerifier.Verify(content, signature, publicKey)` from Task 2
  - `CacheDirectoryManager` from Task 4
  - `TemplateUpdateState` from Task 5
  - `TemplateVersion.TryParse`, `TemplateVersion.Compare` from Task 3
  - `TemplateManifest` from Task 3
  - `TemplateStatus`, `TemplateUpdateResult`, `TemplateUpdateOutcome` from Task 3
- Produces:
  - `ITemplatePackProvider` interface: `Status` property, `CheckForUpdate(CancellationToken)`, `GetCachedTemplatePath(string server)`
  - `TemplatePackProvider` implementation (singleton)

**This is the largest task.** `TemplatePackProvider` orchestrates the full download-verify-extract pipeline:

1. Concurrency guard (`Interlocked.CompareExchange`)
2. Throttle/backoff check (`TemplateUpdateState.IsEligibleForCheck`)
3. Fetch release metadata (GitHub releases API JSON)
4. Version comparison (reject downgrade/same)
5. Download zip + sig to memory (stream with 10MB cap, 30s timeout)
6. Signature verification
7. Extract via `CacheDirectoryManager`
8. Update state
9. Structured logging for all events per spec §7

**Constructor:**
- `TemplatePackProvider(IHttpClientFactory? httpClientFactory, WhoisOptions options, ILogger<TemplatePackProvider> logger, MinisignVerifier verifier, CacheDirectoryManager cache, TemplateUpdateState state)`
- For non-DI: secondary constructor creates static `Lazy<HttpClient>` with `PooledConnectionLifetime` (net8.0+)

**Test approach:** All HTTP tests use a custom `HttpMessageHandler` injected via `IHttpClientFactory` substitute. No real network calls. Tests create real temp directories for cache operations.

- [ ] **Step 1:** Write test `CheckForUpdate_Success_DownloadsAndExtractsPack` — mock HTTP returns release metadata JSON, zip bytes, sig bytes. Use the test minisign keypair from Task 2 to sign a real zip. Verify `Status` reflects new version, cache directory contains extracted files.
- [ ] **Step 2:** Write test `CheckForUpdate_AlreadyUpToDate_ReturnsAlreadyUpToDate` — mock HTTP returns metadata with same version as current. Verify no download occurs.
- [ ] **Step 3:** Write test `CheckForUpdate_DowngradeRejected_ReturnsFailed` — mock HTTP returns metadata with older version. Verify logged and rejected.
- [ ] **Step 4:** Write tests for HTTP error paths: `CheckForUpdate_HttpError_ReturnsFailed` (404, 500), `CheckForUpdate_NetworkError_ReturnsFailed` (handler throws), `CheckForUpdate_NonHttpsUrl_ReturnsFailed`, `CheckForUpdate_ResponseTooLarge_ReturnsFailed`, `CheckForUpdate_RedirectToHttp_ReturnsFailed`
- [ ] **Step 5:** Write test `CheckForUpdate_SignatureInvalid_ReturnsFailed` — valid zip but wrong signature. Verify pack discarded.
- [ ] **Step 6:** Write test `CheckForUpdate_ConcurrentCalls_SecondReturnsSkipped` — fire two calls simultaneously, verify only one HTTP round-trip, second returns `Skipped`.
- [ ] **Step 7:** Write test `CheckForUpdate_NeverThrows_ReturnsFailedOnUnexpectedException` — handler throws `OutOfMemoryException`, `TaskCanceledException`, bare `Exception`. Verify each returns `Failed`, never propagates.
- [ ] **Step 8:** Write tests for backoff integration: `CheckForUpdate_InBackoff_ReturnsSkipped`, `CheckForUpdate_AfterBackoffExpires_Retries`
- [ ] **Step 9:** Write test `CheckForUpdate_DiskFailure_DisablesForSession` — mock cache that fails writes. Verify `Status.AutoUpdateEnabled` becomes false, subsequent calls return `Skipped`.
- [ ] **Step 10:** Write test `GetCachedTemplatePath_ReturnsPath_WhenCacheExists`, `GetCachedTemplatePath_ReturnsNull_WhenNoCacheExists`
- [ ] **Step 11:** Write test `CheckForUpdate_PartialFailure_PreviousCacheIntact` — failure during extraction, verify old pack still present and `Status` unchanged.
- [ ] **Step 12:** Write test `CheckForUpdate_CustomUrl_LogsWarning`
- [ ] **Step 13:** Run all tests, verify they fail
- [ ] **Step 14:** Implement `ITemplatePackProvider` interface
- [ ] **Step 15:** Implement `TemplatePackProvider` — constructor, `Status` property, `GetCachedTemplatePath`
- [ ] **Step 16:** Implement `CheckForUpdate` — concurrency guard, eligibility check, metadata fetch
- [ ] **Step 17:** Implement download pipeline — stream-limited download, signature verification, extraction
- [ ] **Step 18:** Implement structured logging for all events per spec §7
- [ ] **Step 19:** Run tests, fix failures iteratively
- [ ] **Step 20:** Run full test suite, verify no regressions
- [ ] **Step 21:** Commit

---

### Task 8: WhoisLookup + DI Integration

**Files:**
- Modify: `src/Whois/WhoisLookup.cs`
- Modify: `src/Whois/WhoisServiceCollectionExtensions.cs`
- Modify: `tests/Whois.Tests/WhoisLookupTest.cs`
- Modify: `tests/Whois.Tests/WhoisServiceCollectionExtensionsTests.cs`

**Interfaces:**
- Consumes:
  - `ITemplatePackProvider` from Task 7
  - `WhoisParser` (now singleton) from Task 6
  - `TemplateStatus`, `TemplateUpdateResult` from Task 3
- Produces: Completed `WhoisLookup` with `TemplateStatus`, `UpdateTemplates`, auto-update trigger. Completed DI registration.

**What changes:**

`WhoisLookup`:
1. Add `private readonly ITemplatePackProvider _packProvider` field
2. Add `private int _autoUpdateTriggered = 0` field
3. Full DI constructor: accept `ITemplatePackProvider` and `WhoisParser` (remove `Parser = new WhoisParser()`)
4. Non-DI constructors: create `TemplatePackProvider` internally (with static `HttpClient`), use static shared `WhoisParser` instance
5. `TemplateStatus` property: delegates to `_packProvider.Status`
6. `UpdateTemplates`: delegates to `_packProvider.CheckForUpdate`
7. `Lookup(WhoisRequest)`: add auto-update trigger at top (per-instance `Interlocked` guard, fire-and-forget `Task.Run`)
8. Parser property: change from `new WhoisParser()` to injected/shared instance. Pass `_packProvider.GetCachedTemplatePath` as the cache resolver.

`WhoisServiceCollectionExtensions`:
1. Add `services.AddHttpClient("TemplatePackProvider")`
2. Add `services.AddSingleton<CacheDirectoryManager>()` (factory that reads `WhoisOptions.TemplateCacheDirectory`)
3. Add `services.AddSingleton<TemplateUpdateState>()`
4. Add `services.AddSingleton<MinisignVerifier>()`
5. Add `services.AddSingleton<ITemplatePackProvider, TemplatePackProvider>()`
6. Add `services.AddSingleton<WhoisParser>(sp => new WhoisParser(server => sp.GetRequiredService<ITemplatePackProvider>().GetCachedTemplatePath(server)))`
7. Change `WhoisLookup` registration to include new dependencies

**Test approach:**

- [ ] **Step 1:** Update existing `WhoisLookupTest` constructor to work with the new `WhoisLookup` constructor signature (still using NSubstitute mocks for `ITemplatePackProvider`). Run existing tests to verify no regression.
- [ ] **Step 2:** Write test `TemplateStatus_DefaultsToEmbedded` — new `WhoisLookup()` has `TemplateStatus.Source == Embedded` and `CurrentVersion == "embedded"`
- [ ] **Step 3:** Write test `UpdateTemplates_DelegatesToPackProvider` — mock `ITemplatePackProvider`, call `UpdateTemplates`, verify `CheckForUpdate` was called
- [ ] **Step 4:** Write test `Lookup_WithAutoUpdate_TriggersBackgroundCheck` — set `AutoUpdateTemplates = true`, call `Lookup`, verify `CheckForUpdate` was called on the provider (use `ManualResetEventSlim` in mock to synchronise)
- [ ] **Step 5:** Write test `Lookup_WithAutoUpdate_DoesNotBlockQuery` — verify `Lookup` returns before `CheckForUpdate` completes (mock with delay)
- [ ] **Step 6:** Write test `Lookup_MultipleCallsWithAutoUpdate_TriggersOnce` — call `Lookup` twice, verify `CheckForUpdate` called at most once per instance
- [ ] **Step 7:** Update `WhoisServiceCollectionExtensionsTests`: verify `ITemplatePackProvider` and `WhoisParser` are registered and resolvable. Verify `WhoisParser` is singleton (same instance returned twice). Verify `ITemplatePackProvider` is singleton.
- [ ] **Step 8:** Run tests, verify they fail
- [ ] **Step 9:** Implement `WhoisLookup` changes
- [ ] **Step 10:** Implement `WhoisServiceCollectionExtensions` changes
- [ ] **Step 11:** Run tests, verify all pass
- [ ] **Step 12:** Run full test suite (`dotnet test tests/Whois.Tests/Whois.Tests.csproj`), verify no regressions
- [ ] **Step 13:** Run full solution build (`dotnet build Whois.sln`), verify clean build
- [ ] **Step 14:** Commit

---

### Task 9: End-to-End Integration Tests

**Files:**
- Create: `tests/Whois.Tests/Templates/TemplateUpdateIntegrationTests.cs`

**Interfaces:**
- Consumes: all previous tasks
- Produces: integration tests validating the full pipeline

These tests exercise the complete flow: `WhoisLookup` → `TemplatePackProvider` → download → verify → extract → parser loads from cache. Uses mocked HTTP (via `HttpMessageHandler`) but real filesystem operations (temp directories).

- [ ] **Step 1:** Write test `UpdateTemplates_EndToEnd_TemplatesUsedForParsing` — create a real template zip signed with test keypair, mock HTTP to serve it, call `UpdateTemplates`, then call `Parse` for a server in the pack, verify cached template used
- [ ] **Step 2:** Write test `CacheHitBypass_AlreadyQueriedServer_UsesOldTemplates` — query a server (loads embedded), update cache with new pack, query same server again, verify old templates still used
- [ ] **Step 3:** Write test `CacheHitBypass_NewServer_UsesCachedTemplates` — update cache, query a server not yet queried, verify cached templates used
- [ ] **Step 4:** Write test `TemplateStatus_LifecycleTransitions` — verify status transitions: embedded → cached (after update) → error state (after failure)
- [ ] **Step 5:** Write test `SessionDisable_VisibleAcrossInstances` — trigger disk failure on singleton provider, create new `WhoisLookup` instance sharing same provider, verify `AutoUpdateEnabled` is false
- [ ] **Step 6:** Run tests, verify they fail
- [ ] **Step 7:** Implementation should already be complete from previous tasks — fix any integration issues discovered
- [ ] **Step 8:** Run full test suite, verify all pass
- [ ] **Step 9:** Commit

---

### Task 10: Final Validation + Cleanup

**Files:**
- No new files
- Potential fixes to any files from previous tasks

This task is a validation pass, not a feature implementation.

- [ ] **Step 1:** Run full solution build: `dotnet build Whois.sln`
- [ ] **Step 2:** Run all unit tests: `dotnet test tests/Whois.Tests/Whois.Tests.csproj` — verify all pass, note skip count
- [ ] **Step 3:** Run WhoisRefresh tests: `dotnet test tests/WhoisRefresh.Tests/WhoisRefresh.Tests.csproj` — verify no regressions from WhoisParser singleton change
- [ ] **Step 4:** Verify test output is pristine — no unvalidated error logs in test output
- [ ] **Step 5:** Review all new files for `TreatWarningsAsErrors` compliance — fix any warnings
- [ ] **Step 6:** Verify the public API surface matches the spec: `IWhoisLookup` has `TemplateStatus` and `UpdateTemplates`, `WhoisOptions` has all 4 new properties, all types are `sealed` where specified
- [ ] **Step 7:** Commit any fixes
- [ ] **Step 8:** Final commit message summarising Plan 3 completion
