# Refresh Tool Design (Plan 2)

## Overview

A .NET console app (`tools/WhoisRefresh/`) that queries live WHOIS servers, saves responses, detects parsing drift against a baseline, and manages a rolling PR for breakages. Part of the WHOIS Pattern Refresh System.

## Decisions

- **Architecture:** Monolithic console app with Spectre.Cli (Approach A)
- **Tests location:** `tests/WhoisRefresh.Tests/`
- **Baseline/artifacts location:** `tools/WhoisRefresh/refresh-results.json` (committed), drift reports `.gitignore`d in same directory
- **Bootstrap:** `bootstrap` subcommand of the refresh tool (not a separate script)
- **Sample rename:** Deferred. Refresh tool writes new samples as `{domain}.txt`; old samples keep current names
- **PR management:** `IDriftReporter` interface with `gh` CLI implementation
- **Rate limiting:** `Task.WhenAll` with sequential loops per rate group, 5s delay
- **Throttled/reserved samples:** Not listed in `domains.jsonc`; servers included with queryable statuses only

---

## Project Structure

```
tools/WhoisRefresh/
├── WhoisRefresh.csproj
├── Program.cs                    # Spectre.Cli app setup
├── Commands/
│   ├── RefreshCommand.cs
│   ├── DetectCommand.cs
│   └── BootstrapCommand.cs
├── Domain/
│   ├── DomainRegistry.cs         # Loads/validates domains.jsonc
│   ├── RefreshResult.cs          # Result models
│   ├── DriftClassification.cs    # Drift types + classifier
│   └── DriftReport.cs            # Report generation (JSON + MD)
├── Infrastructure/
│   ├── IDriftReporter.cs         # Interface for PR management
│   ├── GhCliDriftReporter.cs     # gh CLI implementation
│   ├── IFileSystem.cs            # File I/O abstraction
│   ├── PhysicalFileSystem.cs     # Real file system
│   └── ConsoleOutput.cs          # Spectre vs plain text (CI detection)
├── domains.jsonc                  # Domain registry (committed)
└── refresh-results.json           # Baseline (committed)

tests/WhoisRefresh.Tests/
├── WhoisRefresh.Tests.csproj
├── DomainRegistryTests.cs
├── RefreshCommandTests.cs
├── DetectCommandTests.cs
├── BootstrapCommandTests.cs
└── DriftClassificationTests.cs
```

**Dependencies:**
- Project reference to `src/Whois/` (for `WhoisParser`, `ITcpReader`)
- `Spectre.Console` + `Spectre.Cli`
- `System.Text.Json` (JSONC parsing via `JsonCommentHandling.Skip` + `AllowTrailingCommas`)

---

## Domain Registry (`domains.jsonc`)

### Schema

```jsonc
{
  "servers": {
    "whois.nic.uk": {
      // Research comments about server behavior
      "tld": "uk",
      "static": false,        // optional, default false
      "rateGroup": null,      // optional, servers sharing infra
      "domains": {
        "found": ["google.co.uk", "bbc.co.uk"],
        "not-found": ["u34jedzcq.co.uk"]
      }
    }
  }
}
```

### Loading & Validation

- Parse with `System.Text.Json` using `JsonCommentHandling.Skip` + `AllowTrailingCommas`
- Validate domain names: reject any containing `/`, `\`, or `..`
- Validate status keys against known set (`found`, `not-found`, `throttled`, `reserved`, `suspended`, `inactive`)
- Duplicate domain detection (same domain under multiple statuses for one server = error)

### Bootstrap Subcommand

- Scans `tests/Whois.Tests/Parsing/**/*ParsingTests.cs`
- Extracts `SampleReader.Read(server, tld, status, filename)` calls
- Extracts corresponding `response.DomainName.ToString()` assertions
- Groups by server, builds registry entries
- Statuses without domain name assertions (throttled) are omitted
- Writes `domains.jsonc` with placeholder comments

---

## Refresh Command

### Flow

1. Load `domains.jsonc`, validate
2. Group servers by rate group (servers without `rateGroup` are each their own group)
3. Skip servers with `static: true`
4. Launch one async task per rate group via `Task.WhenAll`
5. Within each group, query domains sequentially with 5s delay between queries
6. For each domain:
   - Query via `ITcpReader.Read(server, 43, domain, encoding, 30, cancellationToken)`
   - Cap response at 64KB
   - Save raw response to `tests/Whois.Tests/Samples/{server}/{tld}/{status}/{domain}.txt`
   - Parse with `WhoisParser.Parse(server, content)`
   - Record result (matched template, extracted fields, or error)
7. If parsed status differs from expected status: save to actual status directory, flag mismatch
8. Prune entries from `refresh-results.json` for domains removed from `domains.jsonc`
9. Write updated `refresh-results.json`

### Console Output

- **Local:** Spectre progress table (server | status | domains queried)
- **CI** (`GITHUB_ACTIONS` env var): plain text, no ANSI escapes

### Error Handling Per Query

| Condition | Error Type |
|-----------|-----------|
| Network timeout | `Timeout` |
| Connection refused | `ConnectionRefused` |
| Response > 64KB | `ResponseTooLarge` (truncate) |
| No template match | `ParseFailure` |
| Other exception | `Unknown` |

Partial failures don't abort the run. Results collected for all successful queries.

---

## Detect Command (Drift Detection)

### Flow

1. Load current `refresh-results.json` (just written by `refresh` command, or from a manual run)
2. Load previous baseline — the last committed `refresh-results.json` (retrieved via `git show HEAD:tools/WhoisRefresh/refresh-results.json`)
3. Compare per-domain results, classify changes
4. Generate reports
5. If breakages found: invoke `IDriftReporter` to create/update PR

### Classification Rules

| Condition | Classification | Severity |
|-----------|---------------|----------|
| Previously matched a template, now matches nothing | No match | Breakage |
| Fewer extracted fields than baseline | Field regression | Breakage |
| Different template matches, fields equal or better | Template shift | Info |
| Parsed status ≠ expected status in `domains.jsonc` | Status mismatch | Drift |
| New domain (no baseline entry) | New entry | Info |
| Query error (timeout, refused, etc.) | Error | Warning |

### Report Generation

- `drift-report.json` — structured per-domain classification, field diffs, template names
- `drift-report.md` — rendered table for PR body; breakages first, then drift, then info
- For breakages: includes first 50 divergent lines between previous and current raw response

### PR Management (via `IDriftReporter`)

When breakages are found:
1. Check if `template-drift` branch has commits not in `main`
   - If yes (human working on it): create `template-drift/YYYY-MM-DD` instead
   - If no: create/force-update `template-drift` branch
2. Commit updated samples + drift report
3. Create or update rolling PR (find existing open PR, update it; don't create duplicates)

When no breakages: no PR, log summary only.

### CI Output

- `::error::` — breakages (no match, field regression)
- `::warning::` — persistent server failures, status mismatches
- `::notice::` — template shifts, informational changes

---

## Testing Strategy

### DomainRegistryTests

- Valid JSONC parsing (comments, trailing commas)
- Domain validation (rejects `/`, `\`, `..`)
- Duplicate domain detection
- `static` flag respected (skipped servers)
- Rate group grouping logic

### RefreshCommandTests

- Test double for `ITcpReader` (deterministic responses)
- `IFileSystem` abstraction (verifies correct paths, no real disk I/O)
- Rate group parallelism: different groups concurrent, same group sequential
- 64KB response cap enforced
- Partial failure: some servers fail, others succeed
- Status mismatch: saves to actual status directory
- Prunes removed domains from results

### DetectCommandTests

- Crafted baseline + current result pairs
- No match → breakage
- Field regression → breakage
- Template shift → info
- Status mismatch → drift
- First run (no baseline) → all entries "new", no breakages
- Empty results handling

### DriftReporterTests

- `IDriftReporter` mock verifies correct branch/PR logic
- Branch conflict detection (human commits on `template-drift`)
- No duplicates (existing open PR updated)

### BootstrapCommandTests

- Parses test file patterns correctly
- Handles missing `DomainName` assertions (skips gracefully)
- Generates valid JSONC structure
