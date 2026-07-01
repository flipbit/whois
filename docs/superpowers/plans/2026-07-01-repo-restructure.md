# Repo Restructure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure the flat .NET project layout into standard `src/`, `tests/`, `tools/`, `docs/` directories.

**Architecture:** Use `git mv` to relocate all project directories, then update relative paths in the solution file, project references, CI config, and documentation. The solution file stays at root.

**Tech Stack:** .NET, MSBuild, git

---

### Task 1: Commit any outstanding changes

**Files:**
- None

- [ ] **Step 1: Check for uncommitted changes**

```bash
git status
```

If there are uncommitted changes or untracked files, commit or stash them before proceeding.

- [ ] **Step 2: Create a working branch**

```bash
git checkout -b restructure-to-standard-layout
```

- [ ] **Step 3: Commit**

Commit the CLAUDE.md if it's untracked:

```bash
git add CLAUDE.md
git commit -m "Add CLAUDE.md"
```

---

### Task 2: Move project directories with git mv

**Files:**
- Move: `Whois/` → `src/Whois/`
- Move: `Whois.Tests/` → `tests/Whois.Tests/`
- Move: `Whois.Tests.Integration/` → `tests/Whois.Tests.Integration/`
- Move: `Whois.Console/` → `tools/Whois.Console/`
- Move: `Docs/` → `docs/` (case change requires two-step on macOS)

- [ ] **Step 1: Create target directories**

```bash
mkdir -p src tests tools
```

- [ ] **Step 2: Move production source**

```bash
git mv Whois src/Whois
```

- [ ] **Step 3: Move unit tests**

```bash
git mv Whois.Tests tests/Whois.Tests
```

- [ ] **Step 4: Move integration tests**

```bash
git mv Whois.Tests.Integration tests/Whois.Tests.Integration
```

- [ ] **Step 5: Move console tool**

```bash
git mv Whois.Console tools/Whois.Console
```

- [ ] **Step 6: Rename Docs to docs (two-step for case-insensitive filesystem)**

```bash
git mv Docs docs-tmp
git mv docs-tmp docs
```

- [ ] **Step 7: Commit the moves**

```bash
git add -A
git commit -m "Move projects to src/, tests/, tools/, docs/ structure"
```

---

### Task 3: Update solution file project paths

**Files:**
- Modify: `Whois.sln`

The solution file has 4 project entries with relative paths that need updating.

- [ ] **Step 1: Update Whois.Console path**

In `Whois.sln`, change:
```
"Whois.Console", "Whois.Console\Whois.Console.csproj"
```
to:
```
"Whois.Console", "tools\Whois.Console\Whois.Console.csproj"
```

- [ ] **Step 2: Update Whois.Tests path**

Change:
```
"Whois.Tests", "Whois.Tests\Whois.Tests.csproj"
```
to:
```
"Whois.Tests", "tests\Whois.Tests\Whois.Tests.csproj"
```

- [ ] **Step 3: Update Whois path**

Change:
```
"Whois", "Whois\Whois.csproj"
```
to:
```
"Whois", "src\Whois\Whois.csproj"
```

- [ ] **Step 4: Update Whois.Tests.Integration path**

Change:
```
"Whois.Tests.Integration", "Whois.Tests.Integration\Whois.Tests.Integration.csproj"
```
to:
```
"Whois.Tests.Integration", "tests\Whois.Tests.Integration\Whois.Tests.Integration.csproj"
```

- [ ] **Step 5: Commit**

```bash
git add Whois.sln
git commit -m "Update solution file paths for new directory structure"
```

---

### Task 4: Update ProjectReference paths in .csproj files

**Files:**
- Modify: `tests/Whois.Tests/Whois.Tests.csproj:19`
- Modify: `tests/Whois.Tests.Integration/Whois.Tests.Integration.csproj:15`
- Modify: `tools/Whois.Console/Whois.Console.csproj:27`

All three projects reference `../Whois/Whois.csproj`. After the move, the relative paths change.

- [ ] **Step 1: Update Whois.Tests ProjectReference**

In `tests/Whois.Tests/Whois.Tests.csproj`, change:
```xml
<ProjectReference Include="..\Whois\Whois.csproj" />
```
to:
```xml
<ProjectReference Include="..\..\src\Whois\Whois.csproj" />
```

- [ ] **Step 2: Update Whois.Tests.Integration ProjectReference**

In `tests/Whois.Tests.Integration/Whois.Tests.Integration.csproj`, change:
```xml
<ProjectReference Include="..\Whois\Whois.csproj" />
```
to:
```xml
<ProjectReference Include="..\..\src\Whois\Whois.csproj" />
```

- [ ] **Step 3: Update Whois.Console ProjectReference**

In `tools/Whois.Console/Whois.Console.csproj`, change:
```xml
<ProjectReference Include="..\Whois\Whois.csproj" />
```
to:
```xml
<ProjectReference Include="..\..\src\Whois\Whois.csproj" />
```

- [ ] **Step 4: Commit**

```bash
git add tests/Whois.Tests/Whois.Tests.csproj tests/Whois.Tests.Integration/Whois.Tests.Integration.csproj tools/Whois.Console/Whois.Console.csproj
git commit -m "Update ProjectReference paths for new directory structure"
```

---

### Task 5: Update CI configuration (appveyor.yml)

**Files:**
- Modify: `appveyor.yml`

- [ ] **Step 1: Update restore path**

Change:
```yaml
  - cmd: dotnet restore ./Whois/Whois.csproj --verbosity m
```
to:
```yaml
  - cmd: dotnet restore ./src/Whois/Whois.csproj --verbosity m
```

- [ ] **Step 2: Update build commands**

Change:
```yaml
  - cmd: dotnet build ./Whois/Whois.csproj -c Release -f netstandard2.0
  - cmd: dotnet build ./Whois/Whois.csproj -c Release -f net452
  - cmd: dotnet pack ./Whois/Whois.csproj -c Release
```
to:
```yaml
  - cmd: dotnet build ./src/Whois/Whois.csproj -c Release -f netstandard2.0
  - cmd: dotnet build ./src/Whois/Whois.csproj -c Release -f net452
  - cmd: dotnet pack ./src/Whois/Whois.csproj -c Release
```

- [ ] **Step 3: Update test restore path**

Change:
```yaml
  - cmd: dotnet restore ./Whois.Tests/Whois.Tests.csproj --verbosity m
```
to:
```yaml
  - cmd: dotnet restore ./tests/Whois.Tests/Whois.Tests.csproj --verbosity m
```

- [ ] **Step 4: Update test execution directory**

Change:
```yaml
  - cmd: cd Whois.Tests
```
to:
```yaml
  - cmd: cd tests/Whois.Tests
```

- [ ] **Step 5: Update build output comment**

Change:
```yaml
  # output will be in ./Whois/Whois/bin/Release/{framework}
```
to:
```yaml
  # output will be in ./src/Whois/bin/Release/{framework}
```

- [ ] **Step 6: Commit**

```bash
git add appveyor.yml
git commit -m "Update appveyor.yml paths for new directory structure"
```

---

### Task 6: Update CLAUDE.md documentation

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update build and test commands**

Update the Build & Test Commands section to reflect new paths:
- `dotnet test Whois.Tests/Whois.Tests.csproj` → `dotnet test tests/Whois.Tests/Whois.Tests.csproj`
- `dotnet test Whois.Tests.Integration/Whois.Tests.Integration.csproj` → `dotnet test tests/Whois.Tests.Integration/Whois.Tests.Integration.csproj`
- `dotnet build Whois/Whois.csproj -c Release -f netstandard2.0` → `dotnet build src/Whois/Whois.csproj -c Release -f netstandard2.0`

- [ ] **Step 2: Update architecture references**

Update any references to directory paths like `Whois/Resources/`, `Whois.Tests/Samples/`, `Whois.Tests/Parsing/` to use the new `src/` and `tests/` prefixed paths.

- [ ] **Step 3: Update key conventions**

Update references like `Resources/<server>/<tld>/` and `Whois.Tests/Samples/<server>/<tld>/` to `src/Whois/Resources/` and `tests/Whois.Tests/Samples/`.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "Update CLAUDE.md paths for new directory structure"
```

---

### Task 7: Verify build and tests pass

**Files:**
- None (verification only)

- [ ] **Step 1: Restore packages**

```bash
dotnet restore Whois.sln
```

Expected: successful restore with no errors.

- [ ] **Step 2: Build the solution**

```bash
dotnet build Whois.sln
```

Expected: all 4 projects build successfully.

- [ ] **Step 3: Run unit tests**

```bash
dotnet test tests/Whois.Tests/Whois.Tests.csproj
```

Expected: all tests pass.

- [ ] **Step 4: If any step fails, fix the issue and re-run**

Common issues:
- Missed a path reference — grep for old paths like `Whois\Whois.csproj` or `../Whois/`
- EmbeddedResource paths are relative to the .csproj and should not need changing (they moved with the project)

- [ ] **Step 5: Commit any fixes**

```bash
git add -A
git commit -m "Fix any remaining path issues from restructure"
```
