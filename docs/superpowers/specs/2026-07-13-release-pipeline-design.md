# Plan 4: Release Pipeline & GitHub Actions — Design Spec

## Overview

Plan 4 adds the infrastructure to package, sign, and publish versioned template packs as GitHub releases, plus a weekly automated refresh workflow. This builds on Plans 1–3: the normalised directory structure, the WhoisRefresh tool, and the client-side template update mechanism.

## Scope

- Spec sections 5 (Template Release Pipeline), 7 (GitHub Action Workflows), 9 (Testing - GitHub Actions)
- New `package` command in WhoisRefresh tool
- Two new GitHub Action workflows
- Production minisign keypair generation
- Manual GitHub Environment setup (documented steps)

---

## 1. The `package` Command

New Spectre.Cli command in `tools/WhoisRefresh/`: `package <repo-root> --version <calver> [--previous-manifest <path>] [--output <dir>]`

### Behaviour

1. Enumerates all template files under `src/Whois/Resources/**/*.txt`
2. Computes SHA-256 hash per template file
3. Computes an overall content hash: sort template paths ascending by UTF-8 ordinal, concatenate each file's lowercase hex SHA-256 with no separator, then SHA-256 the resulting UTF-8 string. The final hash is lowercase hex.
4. Builds `manifest.json` using the existing `TemplateManifest` / `TemplateEntry` types
5. Creates a zip containing templates in `{server}/{tld}/{status}/{nn}.txt` structure plus `manifest.json` at the root
6. If `--previous-manifest` is provided, diffs the two manifests (added/removed/modified templates by comparing per-template hashes) and writes `changelog.json` + `changelog.md` alongside the zip. If omitted (first release), changelog files are not generated and the release is created without a notes file.
### Exit Codes

- `0` — success
- `1` — failure (missing templates directory, invalid version, I/O error)

Output file paths are fixed by convention (`./artifacts/templates.zip` etc.), not captured from stdout.

### Output Files (default `./artifacts/`)

- `templates.zip`
- `manifest.json` (standalone copy for upload as release asset — same bytes as the manifest inside the zip)
- `changelog.json` (if previous manifest provided)
- `changelog.md` (if previous manifest provided)

### New Types (all in `tools/WhoisRefresh/`)

- `PackageCommand` / `PackageSettings` — Spectre.Cli command and settings
- `TemplatePackager` — core logic: enumerate, hash, zip, manifest generation. References `TemplateManifest`/`TemplateEntry` from `src/Whois/` via the existing project reference.
- `ChangelogGenerator` — manifest diff → structured changelog (JSON + markdown)

---

## 2. Minisign Keypair & Public Key

### Key Generation

One-time step during Plan 4 implementation:

1. Run `minisign -G` to generate a keypair
2. Public key → replace the test constant `EmbeddedPublicKey` in `TemplatePackProvider.cs`
3. Secret key → stored locally, then added to GitHub Environment secret `MINISIGN_SECRET_KEY` during manual environment setup

### Public Key Format

The existing `EmbeddedPublicKey` constant is already in minisign format (two-line string: untrusted comment + base64). The production key replaces it in the same format.

### Test Impact

Plan 3 tests inject a custom `signatureVerifier` func via the constructor — they don't depend on `EmbeddedPublicKey`. Swapping the constant does not break existing tests.

---

## 3. Template Release Workflow (`whois-template-release.yml`)

### Trigger

```yaml
on:
  push:
    branches: [main]
    paths: ['src/Whois/Resources/**']
```

### Environment

`template-release` — protected GitHub Environment with required reviewers.

### Permissions

`contents: write` for creating releases.

### Steps

1. **Checkout** — `actions/checkout@v4` (default `fetch-depth: 1` is sufficient; `gh release list` uses the GitHub API, not git history)
2. **Setup .NET** — `actions/setup-dotnet@v4` (net8.0)
3. **Install minisign** — `sudo apt-get install -y minisign`
4. **Compute CalVer version** — shell script:
   - Today's date as `YYYY.MM.DD`
   - List existing `templates-*` releases via `gh release list --limit 10 --json tagName`
   - If latest release has today's date prefix, increment sequence; otherwise sequence = 1
   - Log the computed version: `echo "::notice::Template pack version: $VERSION"`
   - Output: e.g. `VERSION=2026.07.13.1`
5. **Download previous manifest** — `gh release download <latest-templates-tag> --pattern manifest.json -D ./previous` (skip if no previous release exists)
6. **Build package** — conditionally pass `--previous-manifest` only when the file was actually downloaded:
   ```
   PREV_FLAG=""
   if [ -f ./previous/manifest.json ]; then
     PREV_FLAG="--previous-manifest ./previous/manifest.json"
   fi
   dotnet run --project tools/WhoisRefresh -- package <repo-root> --version $VERSION $PREV_FLAG --output ./artifacts
   ```
7. **Sign** — secure temp file handling:
   ```
   KEYFILE=$(mktemp)
   chmod 600 "$KEYFILE"
   trap 'rm -f "$KEYFILE"' EXIT
   echo "$MINISIGN_SECRET_KEY" > "$KEYFILE"
   minisign -Slm artifacts/templates.zip -s "$KEYFILE" -t "templates-$VERSION"
   ```
   Produces `artifacts/templates.zip.minisig` (minisign co-locates the sig with the signed file).
8. **Create GitHub release** — conditionally use `--notes-file` only when changelog exists:
   ```
   NOTES_FLAG=""
   if [ -f ./artifacts/changelog.md ]; then
     NOTES_FLAG="--notes-file ./artifacts/changelog.md"
   fi
   gh release create templates-$VERSION \
     ./artifacts/templates.zip \
     ./artifacts/templates.zip.minisig \
     ./artifacts/manifest.json \
     --title "Templates $VERSION" \
     $NOTES_FLAG
   ```

### Note

`manifest.json` is attached as a standalone release asset so future runs can download it directly without extracting the zip.

---

## 4. Weekly Refresh Workflow (`whois-refresh.yml`)

### Trigger

Cron (Sunday 02:00 UTC) + `workflow_dispatch` for manual runs.

### Timeout

30 minutes.

### Permissions

`contents: write`, `pull-requests: write`, `issues: write`

### Steps

1. **Checkout** — `actions/checkout@v4`
2. **Setup .NET** — `actions/setup-dotnet@v4` (net8.0)
3. **Staleness check** — shell script:
   - Read `version` timestamp from `tools/WhoisRefresh/refresh-results.json`
   - If older than 28 days, check for existing open issue with `staleness-alert` label
   - If no existing issue, open one via `gh issue create --label staleness-alert`
   - Continue regardless of outcome
4. **Run refresh** — `dotnet run --project tools/WhoisRefresh -- refresh <repo-root>`
5. **Run detect** — `dotnet run --project tools/WhoisRefresh -- detect <repo-root>`
6. **Handle results** — based on detect exit code and `git diff`:
   - **Breakages (exit 1):**
     - Check if `template-drift` branch has human commits not in `main` → use `template-drift/YYYY-MM-DD` instead
     - Create/update branch with changed samples + updated `refresh-results.json`
     - `gh pr create` or `gh pr edit` with drift report markdown as PR body
   - **No breakages but samples changed (exit 0, git diff non-empty):**
     - Commit updated samples + baseline to `refresh/YYYY-MM-DD` branch
     - Create a PR for review
   - **No changes:** nothing to do

### Failure Handling

- `refresh` fails entirely → workflow fails, no baseline update
- `detect` fails → workflow fails, no commits
- Partial success handled by the refresh tool itself (per-server results recorded)

---

## 5. Testing Strategy

### `package` Command Tests (in `tools/WhoisRefresh.Tests/`)

**TemplatePackager:**
- Enumerate templates from a fixture directory
- Verify manifest has correct template count, per-file hashes, and overall content hash
- Content hash determinism: build manifest with templates given in two different insertion orders, assert identical content hash (validates ordinal sort is platform-independent)
- Verify zip structure contains templates + `manifest.json` at expected paths
- Verify all zip entry paths are relative (no leading `/` or drive letter) and contain no `..` components
- End-to-end integrity: re-read templates from the produced zip, recompute content hash, assert it equals `manifest.ContentHash`

**ChangelogGenerator:**
- Given two manifests with known differences (added, removed, modified), verify changelog JSON structure and markdown output
- Markdown format contract: assert section headings present for added/removed/modified groups
- Edge cases: identical manifests (no changes), unparseable previous manifest (log warning, skip changelog)

**PackageCommand integration:**
- End-to-end test with a temp directory containing sample templates
- Verify zip + manifest + changelog are produced correctly
- Verify exit code 0 on success, non-zero when templates directory doesn't exist
- Verify no changelog files produced when `--previous-manifest` is omitted (first-release path)
- Verify clear error when `--previous-manifest` path is provided but file does not exist

### Minisign Round-Trip Test

- Generate a test keypair, sign a payload with minisign CLI format, verify with `MinisignVerifier`
- Validates that production signing flow produces signatures the client-side verifier accepts
- Negative case: generate a second keypair, sign with keypair A, verify against keypair B's public key — must return false (validates key ID mismatch rejection)

### Workflow Testing

- Workflows are kept thin (orchestration only) — all meaningful logic is in testable .NET code
- Packaging → `TemplatePackager`, Changelog → `ChangelogGenerator`, Drift → already tested in Plan 2
- `actionlint` validation is out of scope for Plan 4

---

## 6. Manual Setup Steps

After implementation, the following manual steps are required in the GitHub repo UI:

1. Go to repo **Settings → Environments → New environment**
2. Name: `template-release`
3. Add **required reviewers** (repo maintainers)
4. Add environment secret: `MINISIGN_SECRET_KEY` (the minisign secret key generated during Plan 4)

These steps will be walked through during implementation.

---

## Decisions Record

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Signing approach | Install minisign CLI in runner | Simpler, uses canonical tool, no .NET signing code needed |
| Packaging logic | New `package` command in WhoisRefresh | Co-locates domain knowledge (manifest, CalVer, hashing) |
| Changelog generation | Manifest diff (per-template hashes) | No git dependency in tool, works from content not history |
| CalVer versioning | Computed in workflow shell | Keeps `package` command pure (takes explicit version) |
| Drift PR management | Workflow YAML handles git/gh | Detect command stays focused on analysis |
| Staleness check | Before refresh | Alert fires even if current run also fails |
| Protected environment | Manual setup via GitHub UI | Can't be automated via API |
| actionlint | Out of scope | Keeps Plan 4 focused |
