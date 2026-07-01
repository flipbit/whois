# Whois v4.0 Modernization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Modernize the Whois .NET library from 2018-era tooling to 2026 .NET standards, shipping as v4.0.

**Architecture:** Five-phase approach — each phase changes one dimension at a time. Build foundation first, then migrate test frameworks, then modernize the API surface, then swap dependencies and add DI, then update the console app and docs.

**Tech Stack:** .NET 10 / .NET 8 / .NET Standard 2.0, xUnit, NSubstitute, Microsoft.Extensions.Logging, Microsoft.Extensions.Options, Microsoft.Extensions.DependencyInjection, System.Text.Json

**Design Spec:** `docs/superpowers/specs/2026-07-01-modernization-design.md`

---

## Phase 1: Build Foundation + TFM Updates + CI

### Task 1: Add Directory.Build.props

**Files:**
- Create: `Directory.Build.props`

- [ ] **Step 1: Create Directory.Build.props**

```xml
<Project>
  <PropertyGroup>
    <LangVersion>latest</LangVersion>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <Deterministic>true</Deterministic>
    <!-- Suppress nullable warnings until Phase 3 annotates the codebase -->
    <NoWarn>$(NoWarn);CS8600;CS8601;CS8602;CS8603;CS8604;CS8618;CS8625;CS8767;CS8769</NoWarn>
  </PropertyGroup>

  <!-- Shared package metadata -->
  <PropertyGroup>
    <Authors>Chris Wood</Authors>
    <Company>flipbit.co.uk</Company>
    <Copyright>Copyright 2026 Chris Wood</Copyright>
  </PropertyGroup>
</Project>
```

- [ ] **Step 2: Verify it's picked up**

Run: `dotnet restore Whois.sln && dotnet build Whois.sln --no-restore 2>&1 | head -20`
Expected: Build starts (may fail due to TFM issues — that's fine, we'll fix in next tasks)

- [ ] **Step 3: Commit**

```bash
git add Directory.Build.props
git commit -m "Add Directory.Build.props with shared build settings"
```

### Task 2: Add Directory.Packages.props (Central Package Management)

**Files:**
- Create: `Directory.Packages.props`
- Modify: `src/Whois/Whois.csproj`
- Modify: `tests/Whois.Tests/Whois.Tests.csproj`
- Modify: `tests/Whois.Tests.Integration/Whois.Tests.Integration.csproj`
- Modify: `tools/Whois.Console/Whois.Console.csproj`

- [ ] **Step 1: Create Directory.Packages.props**

```xml
<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <!-- Core library -->
    <PackageVersion Include="Tokenizer" Version="2.2.2" />
    <PackageVersion Include="LibLog" Version="5.0.6" />
    <PackageVersion Include="Microsoft.CSharp" Version="4.7.0" />

    <!-- Console app -->
    <PackageVersion Include="CommandLineParser" Version="2.9.1" />
    <PackageVersion Include="Newtonsoft.Json" Version="13.0.2" />
    <PackageVersion Include="Serilog" Version="2.12.0" />
    <PackageVersion Include="Serilog.Sinks.Console" Version="4.1.0" />
    <PackageVersion Include="Serilog.Sinks.RollingFile" Version="3.3.0" />

    <!-- Test -->
    <PackageVersion Include="Microsoft.NET.Test.Sdk" Version="17.5.0" />
    <PackageVersion Include="Moq" Version="4.18.4" />
    <PackageVersion Include="NUnit" Version="3.13.3" />
    <PackageVersion Include="NUnit3TestAdapter" Version="4.4.2" />
  </ItemGroup>
</Project>
```

- [ ] **Step 2: Remove Version= from all PackageReference elements in all four csproj files**

In each csproj, change `<PackageReference Include="X" Version="Y" />` to `<PackageReference Include="X" />`. For example in `tests/Whois.Tests/Whois.Tests.csproj`:

```xml
  <ItemGroup>
    <PackageReference Include="Microsoft.NET.Test.Sdk" />
    <PackageReference Include="Moq" />
    <PackageReference Include="Newtonsoft.Json" />
    <PackageReference Include="NUnit" />
    <PackageReference Include="NUnit3TestAdapter" />
    <PackageReference Include="Serilog" />
    <PackageReference Include="Serilog.Sinks.Console" />
  </ItemGroup>
```

Apply the same pattern to all four csproj files. Also remove `PrivateAssets="All"` from LibLog in `Whois.csproj` and add it to `Directory.Packages.props` instead:
```xml
<PackageVersion Include="LibLog" Version="5.0.6" PrivateAssets="all" />
```

- [ ] **Step 3: Build to verify**

Run: `dotnet restore Whois.sln && dotnet build Whois.sln --no-restore`
Expected: Successful build

- [ ] **Step 4: Commit**

```bash
git add Directory.Packages.props src/Whois/Whois.csproj tests/Whois.Tests/Whois.Tests.csproj tests/Whois.Tests.Integration/Whois.Tests.Integration.csproj tools/Whois.Console/Whois.Console.csproj
git commit -m "Add Central Package Management via Directory.Packages.props"
```

### Task 3: Update target frameworks

**Files:**
- Modify: `src/Whois/Whois.csproj`
- Modify: `tests/Whois.Tests/Whois.Tests.csproj`
- Modify: `tests/Whois.Tests.Integration/Whois.Tests.Integration.csproj`
- Modify: `tools/Whois.Console/Whois.Console.csproj`

- [ ] **Step 1: Update Whois.csproj target frameworks**

Change:
```xml
<TargetFrameworks>netstandard2.0;net452</TargetFrameworks>
```
To:
```xml
<TargetFrameworks>netstandard2.0;net8.0;net10.0</TargetFrameworks>
```

- [ ] **Step 2: Update test project target frameworks**

In both `tests/Whois.Tests/Whois.Tests.csproj` and `tests/Whois.Tests.Integration/Whois.Tests.Integration.csproj`, change:
```xml
<TargetFramework>netcoreapp2.1</TargetFramework>
```
To:
```xml
<TargetFrameworks>net8.0;net10.0</TargetFrameworks>
```

- [ ] **Step 3: Update console project target framework**

In `tools/Whois.Console/Whois.Console.csproj`, change:
```xml
<TargetFramework>netcoreapp2.1</TargetFramework>
```
To:
```xml
<TargetFramework>net10.0</TargetFramework>
```

- [ ] **Step 4: Remove the `#if !NET452` conditional compilation in TcpReader.cs**

In `src/Whois/Net/TcpReader.cs`, the `#if !NET452` / `#endif` blocks guard `tcpClient?.Dispose()`. Remove the `#if` and `#endif` directives, keeping the `tcpClient?.Dispose()` calls unconditionally.

- [ ] **Step 5: Build and run tests**

Run: `dotnet build Whois.sln && dotnet test tests/Whois.Tests/Whois.Tests.csproj`
Expected: Build succeeds, all tests pass

- [ ] **Step 6: Commit**

```bash
git add src/Whois/Whois.csproj tests/Whois.Tests/Whois.Tests.csproj tests/Whois.Tests.Integration/Whois.Tests.Integration.csproj tools/Whois.Console/Whois.Console.csproj src/Whois/Net/TcpReader.cs
git commit -m "Update target frameworks: drop net452, add net8.0 and net10.0"
```

### Task 4: Simplify Whois.csproj embedded resources

**Files:**
- Modify: `src/Whois/Whois.csproj`

- [ ] **Step 1: Replace the ~660 lines of None Remove + EmbeddedResource Include**

Remove all the individual `<None Remove="Resources\..." />` and `<EmbeddedResource Include="Resources\..." />` entries (lines ~17-673 in the csproj). Replace with:

```xml
  <ItemGroup>
    <EmbeddedResource Include="Resources\**\*.txt" />
  </ItemGroup>
```

- [ ] **Step 2: Build and run tests to verify resources are still embedded correctly**

Run: `dotnet build src/Whois/Whois.csproj && dotnet test tests/Whois.Tests/Whois.Tests.csproj`
Expected: Build succeeds, all parsing tests pass (they depend on embedded resources)

- [ ] **Step 3: Commit**

```bash
git add src/Whois/Whois.csproj
git commit -m "Simplify csproj: replace 660 lines of resource listings with glob"
```

### Task 5: Remove Microsoft.CSharp dependency

**Files:**
- Modify: `src/Whois/Whois.csproj`
- Modify: `Directory.Packages.props`

- [ ] **Step 1: Verify no `dynamic` usage exists**

Run: `grep -r "dynamic " src/Whois/ --include="*.cs" | grep -v "//"`
Expected: No matches (already confirmed during exploration)

- [ ] **Step 2: Remove the PackageReference from Whois.csproj**

Remove the line:
```xml
<PackageReference Include="Microsoft.CSharp" />
```

- [ ] **Step 3: Remove from Directory.Packages.props**

Remove:
```xml
<PackageVersion Include="Microsoft.CSharp" Version="4.7.0" />
```

- [ ] **Step 4: Build and test**

Run: `dotnet build Whois.sln && dotnet test tests/Whois.Tests/Whois.Tests.csproj`
Expected: Build succeeds, all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/Whois/Whois.csproj Directory.Packages.props
git commit -m "Remove unused Microsoft.CSharp dependency"
```

### Task 6: Add .editorconfig

**Files:**
- Create: `.editorconfig`

- [ ] **Step 1: Create .editorconfig**

Examine the existing code style first: the codebase uses 4-space indentation, Allman bracing style, and `var` for local variables. Create `.editorconfig`:

```ini
root = true

[*]
indent_style = space
indent_size = 4
end_of_line = lf
charset = utf-8
trim_trailing_whitespace = true
insert_final_newline = true

[*.cs]
# Use Allman braces (existing style)
csharp_new_line_before_open_brace = all
csharp_new_line_before_else = true
csharp_new_line_before_catch = true
csharp_new_line_before_finally = true

# var preferences (match existing usage)
csharp_style_var_for_built_in_types = true:suggestion
csharp_style_var_when_type_is_apparent = true:suggestion
csharp_style_var_elsewhere = true:suggestion

# Namespace style
csharp_style_namespace_declarations = block_scoped:suggestion

[*.{xml,csproj,props,targets}]
indent_size = 2

[*.{json,yml,yaml}]
indent_size = 2

[*.md]
trim_trailing_whitespace = false
```

- [ ] **Step 2: Commit**

```bash
git add .editorconfig
git commit -m "Add .editorconfig with project code style conventions"
```

### Task 7: Add GitHub Actions build workflow and update CodeQL

**Files:**
- Create: `.github/workflows/build.yml`
- Modify: `.github/workflows/codeql.yml`
- Delete: `appveyor.yml`

- [ ] **Step 1: Create .github/workflows/build.yml**

```yaml
name: Build and Test

on:
  push:
    branches: [master]
  pull_request:
    branches: [master]

jobs:
  build:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    runs-on: ${{ matrix.os }}

    steps:
      - uses: actions/checkout@v4

      - name: Setup .NET
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: |
            8.0.x
            10.0.x

      - name: Restore
        run: dotnet restore Whois.sln

      - name: Build
        run: dotnet build Whois.sln --no-restore

      - name: Test
        run: dotnet test tests/Whois.Tests/Whois.Tests.csproj --no-build --verbosity normal
```

- [ ] **Step 2: Update .github/workflows/codeql.yml**

Update action versions:
- `actions/checkout@v3` → `actions/checkout@v4`
- `github/codeql-action/init@v2` → `github/codeql-action/init@v3`
- `github/codeql-action/autobuild@v2` → `github/codeql-action/autobuild@v3`
- `github/codeql-action/analyze@v2` → `github/codeql-action/analyze@v3`

- [ ] **Step 3: Delete appveyor.yml**

```bash
rm appveyor.yml
```

- [ ] **Step 4: Update Whois.sln to remove appveyor.yml from Solution Items**

Remove the `appveyor.yml = appveyor.yml` line from the `ProjectSection(SolutionItems)` in `Whois.sln`.

- [ ] **Step 5: Build and test locally**

Run: `dotnet build Whois.sln && dotnet test tests/Whois.Tests/Whois.Tests.csproj`
Expected: Build succeeds, all tests pass

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/build.yml .github/workflows/codeql.yml Whois.sln
git rm appveyor.yml
git commit -m "Replace AppVeyor with GitHub Actions, bump CodeQL to v4/v3"
```

### Task 8: Fix SampleReader path separators for cross-platform

**Files:**
- Modify: `tests/Whois.Tests/SampleReader.cs`

The current `SampleReader` uses `..\\..\\..\\Samples` which only works on Windows. Since we now run CI on Ubuntu too, fix this.

- [ ] **Step 1: Check if Path.Join handles this**

`Path.Join` with backslash-containing strings may not normalize on Linux. Update to use `Path.Combine` with separate segments:

```csharp
public string Read(string whoisServer, string tld, string sampleFileName)
{
    var directory = Path.Combine("..", "..", "..", "Samples", whoisServer, tld);
    var fileName = Path.Combine(directory, sampleFileName);

    return File.ReadAllText(fileName);
}
```

- [ ] **Step 2: Run tests**

Run: `dotnet test tests/Whois.Tests/Whois.Tests.csproj`
Expected: All tests pass

- [ ] **Step 3: Commit**

```bash
git add tests/Whois.Tests/SampleReader.cs
git commit -m "Fix SampleReader path separators for cross-platform CI"
```

---

## Phase 2: Test Framework Migration

### Task 9: Replace NUnit and Moq packages with xUnit and NSubstitute

**Files:**
- Modify: `Directory.Packages.props`
- Modify: `tests/Whois.Tests/Whois.Tests.csproj`
- Modify: `tests/Whois.Tests.Integration/Whois.Tests.Integration.csproj`

- [ ] **Step 1: Update Directory.Packages.props**

Remove:
```xml
<PackageVersion Include="Moq" Version="4.18.4" />
<PackageVersion Include="NUnit" Version="3.13.3" />
<PackageVersion Include="NUnit3TestAdapter" Version="4.4.2" />
```

Add:
```xml
<PackageVersion Include="xunit" Version="2.9.3" />
<PackageVersion Include="xunit.runner.visualstudio" Version="3.0.2" />
<PackageVersion Include="NSubstitute" Version="5.3.0" />
```

Note: Check latest stable versions at time of implementation and adjust.

- [ ] **Step 2: Update Whois.Tests.csproj**

Replace:
```xml
<PackageReference Include="Moq" />
<PackageReference Include="NUnit" />
<PackageReference Include="NUnit3TestAdapter" />
```
With:
```xml
<PackageReference Include="xunit" />
<PackageReference Include="xunit.runner.visualstudio" />
<PackageReference Include="NSubstitute" />
```

- [ ] **Step 3: Update Whois.Tests.Integration.csproj**

Replace:
```xml
<PackageReference Include="NUnit" />
<PackageReference Include="NUnit3TestAdapter" />
```
With:
```xml
<PackageReference Include="xunit" />
<PackageReference Include="xunit.runner.visualstudio" />
```

- [ ] **Step 4: Restore to verify packages resolve**

Run: `dotnet restore Whois.sln`
Expected: Restore succeeds (build will fail until test code is migrated)

- [ ] **Step 5: Commit**

```bash
git add Directory.Packages.props tests/Whois.Tests/Whois.Tests.csproj tests/Whois.Tests.Integration/Whois.Tests.Integration.csproj
git commit -m "Replace NUnit/Moq packages with xUnit/NSubstitute"
```

### Task 10: Migrate test infrastructure classes

**Files:**
- Modify: `tests/Whois.Tests/ParsingTests.cs`
- Delete: `tests/Whois.Tests/SerilogConfig.cs`

- [ ] **Step 1: Update ParsingTests base class**

The current `ParsingTests` base class just initializes `SampleReader` in its constructor. This works fine with xUnit (which uses constructors instead of `[SetUp]`). No NUnit references to remove — it's already clean:

```csharp
namespace Whois
{
    public abstract class ParsingTests
    {
        protected ParsingTests()
        {
            SampleReader = new SampleReader();
        }

        protected SampleReader SampleReader { get; }
    }
}
```

Verify it has no `using NUnit.Framework;` — if it does, remove it.

- [ ] **Step 2: Remove SerilogConfig.cs**

`SerilogConfig.Init()` is called in `[SetUp]` methods throughout the parsing tests. With the move away from LibLog+Serilog (Phase 4), and since these tests don't actually depend on log output for assertions, we can remove the `SerilogConfig.Init()` calls during migration. Delete `tests/Whois.Tests/SerilogConfig.cs`.

- [ ] **Step 3: Commit**

```bash
git rm tests/Whois.Tests/SerilogConfig.cs
git add tests/Whois.Tests/ParsingTests.cs
git commit -m "Update test base class, remove SerilogConfig"
```

### Task 11: Migrate parsing test classes (bulk — ~200 files)

**Files:**
- Modify: All `*ParsingTests.cs` files in `tests/Whois.Tests/Parsing/`

All ~200 parsing test classes follow the exact same pattern. Each needs these mechanical transformations:

- [ ] **Step 1: Apply transformations to every parsing test file**

For each file:

1. Replace `using NUnit.Framework;` with `using Xunit;`
2. Remove `using Serilog;` if present
3. Remove `[TestFixture]` attribute
4. Remove the `[SetUp]` method entirely — move its body (minus `SerilogConfig.Init()`) into the constructor
5. Replace `[Test]` with `[Fact]`
6. Replace all NUnit assertions:
   - `Assert.AreEqual(expected, actual)` → `Assert.Equal(expected, actual)`
   - `Assert.Greater(x, y)` → `Assert.True(x > y)`
   - `Assert.IsNull(x)` → `Assert.Null(x)`
   - `Assert.IsNotNull(x)` → `Assert.NotNull(x)`

**Before pattern** (e.g. `UkParsingTests.cs`):
```csharp
using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Uk.Uk
{
    [TestFixture]
    public class UkParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();
            parser = new WhoisParser();
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found.txt");
            var response = parser.Parse("whois.nic.uk", sample);
            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);
            // ...
        }
    }
}
```

**After pattern:**
```csharp
using System;
using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Uk.Uk
{
    public class UkParsingTests : ParsingTests
    {
        private WhoisParser parser;

        public UkParsingTests()
        {
            parser = new WhoisParser();
        }

        [Fact]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.uk", "uk", "found.txt");
            var response = parser.Parse("whois.nic.uk", sample);
            Assert.True(sample.Length > 0);
            Assert.Equal(WhoisStatus.Found, response.Status);
            // ...
        }
    }
}
```

This is mechanical and repetitive. Use search-and-replace tooling across all files.

- [ ] **Step 2: Build to check for compilation errors**

Run: `dotnet build tests/Whois.Tests/Whois.Tests.csproj 2>&1 | tail -20`
Expected: Build succeeds (or reveals remaining assertion patterns to fix)

- [ ] **Step 3: Run all tests**

Run: `dotnet test tests/Whois.Tests/Whois.Tests.csproj --verbosity normal 2>&1 | tail -20`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add tests/Whois.Tests/Parsing/
git commit -m "Migrate parsing tests from NUnit to xUnit"
```

### Task 12: Migrate non-parsing unit test classes

**Files:**
- Modify: `tests/Whois.Tests/WhoisLookupTest.cs`
- Modify: `tests/Whois.Tests/ReadmeTests.cs`
- Modify: `tests/Whois.Tests/Parsers/WhoisParserTests.cs`
- Modify: `tests/Whois.Tests/Servers/IanaServerLookupTest.cs`
- Modify: `tests/Whois.Tests/Servers/WhoisServerCacheTests.cs`
- Modify: `tests/Whois.Tests/HostNameTests.cs`
- Modify: `tests/Whois.Tests/ResourceReaderTests.cs`
- Modify: `tests/Whois.Tests/Net/FakeTcpReader.cs`

- [ ] **Step 1: Migrate WhoisLookupTest.cs (Moq → NSubstitute)**

This is the only file using Moq. Transform:

**Before:**
```csharp
using Moq;
using NUnit.Framework;
// ...
[TestFixture]
public class WhoisLookupTest
{
    private Mock<IWhoisServerLookup> whoisServerLookup;
    private Mock<ITcpReader> tcpReader;

    [SetUp]
    public void SetUp()
    {
        whoisServerLookup = new Mock<IWhoisServerLookup>();
        tcpReader = new Mock<ITcpReader>();
        // ...
        lookup = new WhoisLookup
        {
            TcpReader = tcpReader.Object,
            ServerLookup = whoisServerLookup.Object
        };
    }

    [Test]
    public async Task TestLookupDomain()
    {
        whoisServerLookup
            .Setup(call => call.LookupAsync(request))
            .Returns(Task.FromResult(rootServer));
        tcpReader
            .Setup(call => call.Read(...))
            .Returns(Task.FromResult(result));
        // ...
        whoisServerLookup.Verify(call => call.LookupAsync(request), Times.Never());
    }
}
```

**After:**
```csharp
using NSubstitute;
using Xunit;
// ...
public class WhoisLookupTest
{
    private IWhoisServerLookup whoisServerLookup;
    private ITcpReader tcpReader;
    private WhoisLookup lookup;
    private SampleReader sampleReader;

    public WhoisLookupTest()
    {
        whoisServerLookup = Substitute.For<IWhoisServerLookup>();
        tcpReader = Substitute.For<ITcpReader>();
        sampleReader = new SampleReader();

        lookup = new WhoisLookup
        {
            TcpReader = tcpReader,
            ServerLookup = whoisServerLookup
        };
    }

    [Fact]
    public async Task TestLookupDomain()
    {
        whoisServerLookup.LookupAsync(request).Returns(rootServer);
        tcpReader.Read(...).Returns(result);
        // ...
        await whoisServerLookup.DidNotReceive().LookupAsync(request);
    }
}
```

Key NSubstitute patterns:
- `mock.Setup(x => x.Method(args)).Returns(val)` → `sub.Method(args).Returns(val)`
- `Task.FromResult(val)` → just `val` (NSubstitute handles Task wrapping)
- `mock.Object` → just `sub` (NSubstitute returns the substitute directly)
- `mock.Verify(x => x.Method(args), Times.Never())` → `await sub.DidNotReceive().Method(args)`

Also update the two sync tests (`TestLookupDomainWithEmptyQuery`, `TestLookupDomainWithNullQuery`) — these call `lookup.Lookup()` which is sync. They will need to call `LookupAsync()` instead (since we'll remove sync methods in Phase 3). For now, keep calling the sync methods — they still exist. We'll update these in Phase 3.

- [ ] **Step 2: Migrate remaining test files**

Apply the standard NUnit → xUnit transformations (same as Task 11) to:
- `HostNameTests.cs`
- `WhoisParserTests.cs`
- `IanaServerLookupTest.cs`
- `WhoisServerCacheTests.cs`
- `ResourceReaderTests.cs`
- `ReadmeTests.cs`

Each follows the same pattern: remove `[TestFixture]`, `[SetUp]` → constructor, `[Test]` → `[Fact]`, NUnit assertions → xUnit assertions.

For `ReadmeTests.cs`: also replace `Newtonsoft.Json` usage with `System.Text.Json`:
```csharp
// Before:
var json = JsonConvert.SerializeObject(response, Formatting.Indented);
// After:
var json = System.Text.Json.JsonSerializer.Serialize(response, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
```

- [ ] **Step 3: Update FakeTcpReader.cs**

Remove `IDisposable` implementation if present (it implements `ITcpReader : IDisposable`). The `Dispose()` method on `FakeTcpReader` is a no-op, but it must match the interface until we change the interface in Phase 3.

- [ ] **Step 4: Build and run all tests**

Run: `dotnet build tests/Whois.Tests/Whois.Tests.csproj && dotnet test tests/Whois.Tests/Whois.Tests.csproj --verbosity normal 2>&1 | tail -20`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add tests/Whois.Tests/
git commit -m "Migrate non-parsing tests: Moq to NSubstitute, NUnit to xUnit"
```

### Task 13: Migrate integration tests

**Files:**
- Modify: `tests/Whois.Tests.Integration/Domains/DomainTests.cs`
- Modify: `tests/Whois.Tests.Integration/MultithreadingTests.cs`
- Modify: `tests/Whois.Tests.Integration/Servers/IanaServerLookupTest.cs`
- Modify: `tests/Whois.Tests.Integration/Net/TcpReaderTest.cs`
- Modify: `tests/Whois.Tests.Integration/SampleReader.cs`

- [ ] **Step 1: Apply NUnit → xUnit transformations to all integration test files**

Same mechanical changes as unit tests: `[TestFixture]` removed, `[SetUp]` → constructor, `[Test]` → `[Fact]`, `[Ignore("reason")]` → `[Fact(Skip = "reason")]`, NUnit assertions → xUnit assertions.

For `SampleReader.cs` in the integration project — this uses `JsonConvert.DeserializeObject`. We'll leave this as-is for now (it's needed for the Domains.txt sample data). It will be updated in Phase 5 when we swap Newtonsoft.

- [ ] **Step 2: Remove Serilog packages from unit test project**

In `tests/Whois.Tests/Whois.Tests.csproj`, remove:
```xml
<PackageReference Include="Serilog" />
<PackageReference Include="Serilog.Sinks.Console" />
```

Remove from `Directory.Packages.props` if no other project uses them (check console project — it still does, so keep them in Directory.Packages.props for now).

- [ ] **Step 3: Build and run integration tests**

Run: `dotnet build tests/Whois.Tests.Integration/Whois.Tests.Integration.csproj`
Expected: Build succeeds (don't run integration tests — they need network)

- [ ] **Step 4: Run unit tests to confirm nothing broke**

Run: `dotnet test tests/Whois.Tests/Whois.Tests.csproj`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add tests/
git commit -m "Migrate integration tests to xUnit, remove Serilog from unit tests"
```

### Task 14: Remove Newtonsoft.Json from unit test project

**Files:**
- Modify: `tests/Whois.Tests/Whois.Tests.csproj`

- [ ] **Step 1: Verify ReadmeTests.cs no longer uses Newtonsoft**

Confirm the migration in Task 12 replaced `JsonConvert` with `System.Text.Json.JsonSerializer`.

- [ ] **Step 2: Remove the package reference**

Remove from `tests/Whois.Tests/Whois.Tests.csproj`:
```xml
<PackageReference Include="Newtonsoft.Json" />
```

- [ ] **Step 3: Build and test**

Run: `dotnet build tests/Whois.Tests/Whois.Tests.csproj && dotnet test tests/Whois.Tests/Whois.Tests.csproj`
Expected: Build succeeds, all tests pass

- [ ] **Step 4: Commit**

```bash
git add tests/Whois.Tests/Whois.Tests.csproj
git commit -m "Remove Newtonsoft.Json from unit test project"
```

---

## Phase 3: API Modernization

### Task 15: Remove sync API and AsyncHelper

**Files:**
- Modify: `src/Whois/IWhoisLookup.cs`
- Modify: `src/Whois/WhoisLookup.cs`
- Modify: `src/Whois/Servers/IWhoisServerLookup.cs`
- Modify: `src/Whois/Servers/IanaServerLookup.cs`
- Delete: `src/Whois/AsyncHelper.cs`

- [ ] **Step 1: Update IWhoisLookup.cs**

Remove all sync `Lookup` overloads and drop `IDisposable` inheritance (TcpReader will be stateless after Task 18). Rename `LookupAsync` → `Lookup`:

```csharp
using System.Text;
using System.Threading.Tasks;

namespace Whois
{
    public interface IWhoisLookup
    {
        Task<WhoisResponse> Lookup(string domain);

        Task<WhoisResponse> Lookup(string domain, Encoding encoding);

        Task<WhoisResponse> Lookup(WhoisRequest request);

        void RegisterValidator<T>() where T : class;

        void RegisterTransformer<T>() where T : class;
    }
}
```

- [ ] **Step 2: Update IWhoisServerLookup.cs**

Remove sync `Lookup` and `IDisposable`. Rename `LookupAsync` → `Lookup`:

```csharp
using System.Threading.Tasks;

namespace Whois.Servers
{
    public interface IWhoisServerLookup
    {
        Task<WhoisResponse> Lookup(WhoisRequest request);
    }
}
```

- [ ] **Step 3: Update WhoisLookup.cs**

- Remove all sync `Lookup()` methods
- Rename `LookupAsync` → `Lookup`
- Remove `IDisposable` implementation (`Dispose()` method)
- Remove `using Whois.Net;` if only used for `ITcpReader` disposal
- Update internal calls: `ServerLookup.LookupAsync(request)` → `ServerLookup.Lookup(request)`

- [ ] **Step 4: Update IanaServerLookup.cs**

- Remove sync `Lookup()` method
- Rename `LookupAsync` → `Lookup`
- Remove `IDisposable` implementation
- Remove `AsyncHelper.RunSync` usage

- [ ] **Step 5: Delete AsyncHelper.cs**

```bash
rm src/Whois/AsyncHelper.cs
```

- [ ] **Step 6: Update tests**

In `WhoisLookupTest.cs`, update all `lookup.LookupAsync(request)` calls to `lookup.Lookup(request)`. Update the two sync tests (`TestLookupDomainWithEmptyQuery`, `TestLookupDomainWithNullQuery`) to be async:

```csharp
[Fact]
public async Task TestLookupDomainWithEmptyQuery()
{
    await Assert.ThrowsAsync<ArgumentNullException>(() => lookup.Lookup(string.Empty));
}
```

Update `IanaServerLookupTest.cs`: calls to `lookup.LookupAsync(...)` → `lookup.Lookup(...)`.

Update `ReadmeTests.cs`: remove sync test methods, update async ones.

- [ ] **Step 7: Build and test**

Run: `dotnet build Whois.sln && dotnet test tests/Whois.Tests/Whois.Tests.csproj`
Expected: Build succeeds, all tests pass

- [ ] **Step 8: Commit**

```bash
git add src/Whois/ tests/Whois.Tests/
git rm src/Whois/AsyncHelper.cs
git commit -m "Remove sync API and AsyncHelper, rename methods to drop Async suffix"
```

### Task 16: Add CancellationToken to interfaces

**Files:**
- Modify: `src/Whois/IWhoisLookup.cs`
- Modify: `src/Whois/Net/ITcpReader.cs`
- Modify: `src/Whois/Servers/IWhoisServerLookup.cs`

- [ ] **Step 1: Update IWhoisLookup.cs**

Add `CancellationToken cancellationToken = default` to all methods:

```csharp
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Whois
{
    public interface IWhoisLookup
    {
        Task<WhoisResponse> Lookup(string domain, CancellationToken cancellationToken = default);

        Task<WhoisResponse> Lookup(string domain, Encoding encoding, CancellationToken cancellationToken = default);

        Task<WhoisResponse> Lookup(WhoisRequest request, CancellationToken cancellationToken = default);

        void RegisterValidator<T>() where T : class;

        void RegisterTransformer<T>() where T : class;
    }
}
```

- [ ] **Step 2: Update ITcpReader.cs**

Add `CancellationToken` and remove `IDisposable` (will be stateless after rewrite):

```csharp
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Whois.Net
{
    public interface ITcpReader
    {
        Task<string> Read(string url, int port, string command, Encoding encoding, int timeoutSeconds, CancellationToken cancellationToken = default);
    }
}
```

- [ ] **Step 3: Update IWhoisServerLookup.cs**

```csharp
using System.Threading;
using System.Threading.Tasks;

namespace Whois.Servers
{
    public interface IWhoisServerLookup
    {
        Task<WhoisResponse> Lookup(WhoisRequest request, CancellationToken cancellationToken = default);
    }
}
```

- [ ] **Step 4: Update FakeTcpReader to match new interface**

```csharp
public Task<string> Read(string url, int port, string command, Encoding encoding, int timeoutSeconds, CancellationToken cancellationToken = default)
{
    return Task.FromResult(response);
}
```

Remove `Dispose()` method and `IDisposable` if `ITcpReader` no longer extends it.

- [ ] **Step 5: Build (expect failures in implementations — that's fine, we'll fix in next tasks)**

Run: `dotnet build Whois.sln 2>&1 | grep "error CS" | head -20`
Expected: Compilation errors in `WhoisLookup.cs`, `TcpReader.cs`, `IanaServerLookup.cs` — they don't match the new interfaces yet

- [ ] **Step 6: Commit**

```bash
git add src/Whois/IWhoisLookup.cs src/Whois/Net/ITcpReader.cs src/Whois/Servers/IWhoisServerLookup.cs tests/Whois.Tests/Net/FakeTcpReader.cs
git commit -m "Add CancellationToken to all async interfaces"
```

### Task 17: Create NetStandardShims helper

**Files:**
- Create: `src/Whois/Net/NetStandardShims.cs`

- [ ] **Step 1: Create the centralised #if helper**

```csharp
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Whois.Net
{
    /// <summary>
    /// Centralises all #if conditional compilation for netstandard2.0 compatibility.
    /// On modern TFMs, uses CancellationToken-aware overloads.
    /// On netstandard2.0, falls back to non-cancellable equivalents.
    /// </summary>
    internal static class NetStandardShims
    {
        public static Task ConnectAsync(TcpClient client, string host, int port, CancellationToken cancellationToken)
        {
#if NETSTANDARD2_0
            cancellationToken.ThrowIfCancellationRequested();
            return client.ConnectAsync(host, port);
#else
            return client.ConnectAsync(host, port, cancellationToken).AsTask();
#endif
        }

        public static Task<string?> ReadLineAsync(StreamReader reader, CancellationToken cancellationToken)
        {
#if NETSTANDARD2_0
            cancellationToken.ThrowIfCancellationRequested();
            return reader.ReadLineAsync();
#else
            return reader.ReadLineAsync(cancellationToken).AsTask();
#endif
        }
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add src/Whois/Net/NetStandardShims.cs
git commit -m "Add NetStandardShims for centralised conditional compilation"
```

### Task 18: Rewrite TcpReader (stateless, cancellation-aware)

**Files:**
- Modify: `src/Whois/Net/TcpReader.cs`

- [ ] **Step 1: Rewrite TcpReader to be stateless with proper cancellation**

Replace the entire implementation. The new version:
- Has no instance fields (no shared `tcpClient`/`reader`/`writer`)
- Creates and disposes a `TcpClient` per call
- Uses `CancellationTokenSource.CreateLinkedTokenSource` + `CancelAfter` for timeouts
- No `IDisposable` (nothing to dispose)

```csharp
using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Whois.Net
{
    public class TcpReader : ITcpReader
    {
        public async Task<string> Read(string url, int port, string command, Encoding encoding, int timeoutSeconds, CancellationToken cancellationToken = default)
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

            var token = timeoutCts.Token;

            using var tcpClient = new TcpClient();

            try
            {
                await NetStandardShims.ConnectAsync(tcpClient, url, port, token);

                using var stream = tcpClient.GetStream();
                using var writer = new StreamWriter(stream, encoding) { NewLine = "\r\n" };
                using var reader = new StreamReader(stream, encoding);

                await writer.WriteLineAsync(command);
                await writer.FlushAsync();

                var sb = new StringBuilder();
                string? line;
                while ((line = await NetStandardShims.ReadLineAsync(reader, token)) != null)
                {
                    sb.AppendLine(line);
                }

                return sb.ToString();
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException)
            {
                throw new WhoisException($"Connection to {url}:{port} timed out after {timeoutSeconds} seconds.");
            }
            catch (SocketException ex)
            {
                throw new WhoisException($"Couldn't connect to {url}:{port}: {ex.Message}", ex);
            }
        }
    }
}
```

- [ ] **Step 2: Build**

Run: `dotnet build src/Whois/Whois.csproj`
Expected: May still fail if WhoisLookup/IanaServerLookup haven't been updated yet — that's fine.

- [ ] **Step 3: Commit**

```bash
git add src/Whois/Net/TcpReader.cs
git commit -m "Rewrite TcpReader: stateless, cancellation-aware, no resource leaks"
```

### Task 19: Wire CancellationToken through WhoisLookup and IanaServerLookup

**Files:**
- Modify: `src/Whois/WhoisLookup.cs`
- Modify: `src/Whois/Servers/IanaServerLookup.cs`

- [ ] **Step 1: Update IanaServerLookup**

Add `CancellationToken` parameter to `Lookup` and internal `Download` method. Pass it through to `TcpReader.Read()`:

```csharp
public async Task<WhoisResponse> Lookup(WhoisRequest request, CancellationToken cancellationToken = default)
{
    // ... existing logic ...
    var content = await Download(tld, request, cancellationToken);
    // ...
}

private async Task<string> Download(string tld, WhoisRequest request, CancellationToken cancellationToken)
{
    var result = await TcpReader.Read("whois.iana.org", 43, tld.ToUpper(), request.Encoding, request.TimeoutSeconds, cancellationToken);
    // ...
    return result;
}
```

Also remove `IDisposable` implementation if still present.

- [ ] **Step 2: Update WhoisLookup**

Add `CancellationToken` to all `Lookup` overloads and pass through the chain:

```csharp
public Task<WhoisResponse> Lookup(string domain, CancellationToken cancellationToken = default)
{
    return Lookup(domain, Options.Encoding, cancellationToken);
}

public Task<WhoisResponse> Lookup(string domain, Encoding encoding, CancellationToken cancellationToken = default)
{
    // ... create request ...
    return Lookup(request, cancellationToken);
}

public async Task<WhoisResponse> Lookup(WhoisRequest request, CancellationToken cancellationToken = default)
{
    // ... existing logic, passing cancellationToken to:
    //   ServerLookup.Lookup(request, cancellationToken)
    //   Download(request, ..., cancellationToken)
    //   and checking cancellationToken.ThrowIfCancellationRequested() in the referrer loop
}
```

Update internal `Download` method:
```csharp
private async Task<string> Download(WhoisRequest request, string whoisServer, CancellationToken cancellationToken)
{
    var result = await TcpReader.Read(whoisServer, 43, query, request.Encoding, request.TimeoutSeconds, cancellationToken);
    // ...
}
```

Remove `IDisposable` implementation.

- [ ] **Step 3: Update tests**

In `WhoisLookupTest.cs`, update NSubstitute setups to match new signatures:

```csharp
whoisServerLookup.Lookup(request, Arg.Any<CancellationToken>()).Returns(rootServer);
tcpReader.Read("whois.markmonitor.com", 43, "google.com", Encoding.UTF8, 10, Arg.Any<CancellationToken>()).Returns(sampleResult);
```

Update `IanaServerLookupTest.cs` similarly.

- [ ] **Step 4: Build and test**

Run: `dotnet build Whois.sln && dotnet test tests/Whois.Tests/Whois.Tests.csproj`
Expected: Build succeeds, all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/Whois/WhoisLookup.cs src/Whois/Servers/IanaServerLookup.cs tests/Whois.Tests/
git commit -m "Wire CancellationToken through WhoisLookup and IanaServerLookup"
```

### Task 20: Enable nullable annotations

**Files:**
- Modify: `Directory.Build.props`
- Modify: All source files in `src/Whois/`

- [ ] **Step 1: Remove NoWarn suppressions from Directory.Build.props**

Remove the `<NoWarn>` line that suppresses nullable warnings.

- [ ] **Step 2: Build and capture warnings**

Run: `dotnet build src/Whois/Whois.csproj 2>&1 | grep "warning CS8" | sort -u`
Expected: List of nullable warnings to fix

- [ ] **Step 3: Annotate public API types**

Work through each file, adding `?` to nullable reference type properties and parameters. Key types to annotate:

- `WhoisResponse`: most properties are nullable (domain may not parse, contacts may not exist). `Content` is non-null, `DomainName?`, `Registrar?`, `Registrant?`, `AdminContact?`, `TechnicalContact?`, `BillingContact?`, `ZoneContact?`, `Referrer?`, etc.
- `Contact`: `Name?`, `Organization?`, `Email?`, `TelephoneNumber?`, etc. `Address` should be non-null (initialized to empty list).
- `Registrar`: `Name?`, `WhoisServer?`, `Url?`, `AbuseEmail?`, etc.
- `WhoisRequest`: `Query` non-null (required), `WhoisServer?`, `Encoding` non-null.
- `HostName`: `Value` non-null, `Tld` non-null.
- `WhoisOptions`: all properties non-null.
- `ITcpReader.Read`: return `Task<string>` (non-null).
- `WhoisParser.Parse`: return `WhoisResponse` (non-null).

- [ ] **Step 4: Fix all nullable warnings**

Work through the compiler warnings systematically. Common fixes:
- Add null checks where needed
- Add `!` (null-forgiving) where the code guarantees non-null but the compiler can't see it
- Initialize properties to non-null defaults where appropriate

- [ ] **Step 5: Build with zero warnings**

Run: `dotnet build src/Whois/Whois.csproj -warnaserror`
Expected: Build succeeds with no warnings

- [ ] **Step 6: Run tests**

Run: `dotnet test tests/Whois.Tests/Whois.Tests.csproj`
Expected: All tests pass

- [ ] **Step 7: Commit**

```bash
git add Directory.Build.props src/Whois/
git commit -m "Enable nullable reference types and annotate public API"
```

---

## Phase 4: Dependencies + DI

### Task 21: Replace LibLog with Microsoft.Extensions.Logging

**Files:**
- Modify: `Directory.Packages.props`
- Modify: `src/Whois/Whois.csproj`
- Modify: `src/Whois/WhoisLookup.cs`
- Modify: `src/Whois/Servers/IanaServerLookup.cs`

- [ ] **Step 1: Update packages**

In `Directory.Packages.props`, remove:
```xml
<PackageVersion Include="LibLog" Version="5.0.6" PrivateAssets="all" />
```

Add:
```xml
<PackageVersion Include="Microsoft.Extensions.Logging.Abstractions" Version="9.0.0" />
```

In `src/Whois/Whois.csproj`, replace:
```xml
<PackageReference Include="LibLog" />
```
With:
```xml
<PackageReference Include="Microsoft.Extensions.Logging.Abstractions" />
```

- [ ] **Step 2: Update WhoisLookup.cs**

Replace LibLog with ILogger<T>:

```csharp
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

public class WhoisLookup : IWhoisLookup
{
    private readonly ILogger<WhoisLookup> _logger;

    public WhoisLookup() : this(NullLogger<WhoisLookup>.Instance)
    {
    }

    public WhoisLookup(ILogger<WhoisLookup> logger)
    {
        _logger = logger;
        // ... existing initialization ...
    }

    // Replace Log.Debug(...) calls with _logger.LogDebug(...)
}
```

- [ ] **Step 3: Update IanaServerLookup.cs**

Same pattern:

```csharp
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

public class IanaServerLookup : IWhoisServerLookup
{
    private readonly ILogger<IanaServerLookup> _logger;

    public IanaServerLookup() : this(NullLogger<IanaServerLookup>.Instance)
    {
    }

    public IanaServerLookup(ILogger<IanaServerLookup> logger)
    {
        _logger = logger;
        TcpReader = new TcpReader();
        // ...
    }

    // Replace Log.Debug(...) with _logger.LogDebug(...)
}
```

- [ ] **Step 4: Build and test**

Run: `dotnet build Whois.sln && dotnet test tests/Whois.Tests/Whois.Tests.csproj`
Expected: Build succeeds, all tests pass

- [ ] **Step 5: Commit**

```bash
git add Directory.Packages.props src/Whois/Whois.csproj src/Whois/WhoisLookup.cs src/Whois/Servers/IanaServerLookup.cs
git commit -m "Replace LibLog with Microsoft.Extensions.Logging"
```

### Task 22: Implement Options pattern for WhoisOptions

**Files:**
- Modify: `src/Whois/WhoisOptions.cs`
- Modify: `src/Whois/WhoisRequest.cs`
- Modify: `src/Whois/WhoisLookup.cs`

- [ ] **Step 1: Update WhoisOptions.cs**

Make it a proper options class compatible with `Microsoft.Extensions.Options`:

```csharp
using System.Text;

namespace Whois
{
    public class WhoisOptions
    {
        public Encoding Encoding { get; set; } = Encoding.UTF8;

        public int TimeoutSeconds { get; set; } = 10;

        public bool FollowReferrer { get; set; } = true;
    }
}
```

Remove the static `Defaults` property and static constructor. The defaults are now on the properties themselves.

- [ ] **Step 2: Update WhoisRequest.cs**

Update to use default values directly instead of `WhoisOptions.Defaults`:

```csharp
public class WhoisRequest
{
    public string Query { get; set; } = string.Empty;

    public Encoding Encoding { get; set; } = Encoding.UTF8;

    public int TimeoutSeconds { get; set; } = 10;

    public bool FollowReferrer { get; set; } = true;

    public string? WhoisServer { get; set; }

    public WhoisRequest()
    {
    }

    public WhoisRequest(string domain) : this()
    {
        Query = domain;
    }
}
```

- [ ] **Step 3: Update WhoisLookup.cs to accept IOptions<WhoisOptions>**

```csharp
using Microsoft.Extensions.Options;

public class WhoisLookup : IWhoisLookup
{
    public WhoisOptions Options { get; }

    // Simple constructor for non-DI usage
    public WhoisLookup() : this(new WhoisOptions())
    {
    }

    // Constructor accepting raw options
    public WhoisLookup(WhoisOptions options) : this(options, NullLogger<WhoisLookup>.Instance)
    {
    }

    // Full constructor for DI
    public WhoisLookup(IOptions<WhoisOptions> options, ILogger<WhoisLookup> logger)
        : this(options.Value, logger)
    {
    }

    // Internal constructor that everything chains to
    private WhoisLookup(WhoisOptions options, ILogger<WhoisLookup> logger)
    {
        Options = options;
        _logger = logger;
        Parser = new WhoisParser();
        TcpReader = new TcpReader();
        ServerLookup = new IanaServerLookup();
    }
}
```

Update the `Lookup` methods to apply `Options` defaults to `WhoisRequest` when creating from a string:

```csharp
public Task<WhoisResponse> Lookup(string domain, CancellationToken cancellationToken = default)
{
    return Lookup(domain, Options.Encoding, cancellationToken);
}

public Task<WhoisResponse> Lookup(string domain, Encoding encoding, CancellationToken cancellationToken = default)
{
    var request = new WhoisRequest(domain)
    {
        Encoding = encoding,
        TimeoutSeconds = Options.TimeoutSeconds,
        FollowReferrer = Options.FollowReferrer
    };
    return Lookup(request, cancellationToken);
}
```

- [ ] **Step 4: Update tests**

Update any tests that reference `WhoisOptions.Defaults` to use `new WhoisOptions()` instead.

- [ ] **Step 5: Build and test**

Run: `dotnet build Whois.sln && dotnet test tests/Whois.Tests/Whois.Tests.csproj`
Expected: Build succeeds, all tests pass

- [ ] **Step 6: Commit**

```bash
git add src/Whois/WhoisOptions.cs src/Whois/WhoisRequest.cs src/Whois/WhoisLookup.cs tests/Whois.Tests/
git commit -m "Implement Options pattern for WhoisOptions"
```

### Task 23: Add DI extension method

**Files:**
- Modify: `Directory.Packages.props`
- Modify: `src/Whois/Whois.csproj`
- Create: `src/Whois/WhoisServiceCollectionExtensions.cs`

- [ ] **Step 1: Add DI packages to Directory.Packages.props**

```xml
<PackageVersion Include="Microsoft.Extensions.DependencyInjection.Abstractions" Version="9.0.0" />
<PackageVersion Include="Microsoft.Extensions.Options" Version="9.0.0" />
<PackageVersion Include="Microsoft.Extensions.Options.ConfigurationExtensions" Version="9.0.0" />
```

- [ ] **Step 2: Add package references to Whois.csproj**

```xml
<PackageReference Include="Microsoft.Extensions.DependencyInjection.Abstractions" />
<PackageReference Include="Microsoft.Extensions.Options" />
<PackageReference Include="Microsoft.Extensions.Options.ConfigurationExtensions" />
```

- [ ] **Step 3: Create WhoisServiceCollectionExtensions.cs**

```csharp
using System;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Whois.Net;
using Whois.Servers;

namespace Whois
{
    public static class WhoisServiceCollectionExtensions
    {
        public static IServiceCollection AddWhois(this IServiceCollection services, Action<WhoisOptions>? configure = null)
        {
            var optionsBuilder = services.AddOptions<WhoisOptions>();

            if (configure != null)
            {
                optionsBuilder.Configure(configure);
            }

            services.AddTransient<ITcpReader, TcpReader>();
            services.AddTransient<IWhoisServerLookup, IanaServerLookup>();
            services.AddTransient<IWhoisLookup, WhoisLookup>();

            return services;
        }

        public static IServiceCollection AddWhois(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddOptions<WhoisOptions>().Bind(configuration);

            services.AddTransient<ITcpReader, TcpReader>();
            services.AddTransient<IWhoisServerLookup, IanaServerLookup>();
            services.AddTransient<IWhoisLookup, WhoisLookup>();

            return services;
        }
    }
}
```

- [ ] **Step 4: Update constructors for DI resolution**

Ensure `WhoisLookup` and `IanaServerLookup` constructors accept their dependencies for DI:

`IanaServerLookup` needs to accept `ITcpReader` and `ILogger<IanaServerLookup>`:
```csharp
public IanaServerLookup(ITcpReader tcpReader, ILogger<IanaServerLookup> logger)
{
    TcpReader = tcpReader;
    _logger = logger;
}
```

`WhoisLookup` full DI constructor:
```csharp
public WhoisLookup(IOptions<WhoisOptions> options, ILogger<WhoisLookup> logger, ITcpReader tcpReader, IWhoisServerLookup serverLookup)
{
    Options = options.Value;
    _logger = logger;
    TcpReader = tcpReader;
    ServerLookup = serverLookup;
    Parser = new WhoisParser();
}
```

Keep the parameterless constructor for non-DI usage.

- [ ] **Step 5: Write tests for DI registration**

Create `tests/Whois.Tests/WhoisServiceCollectionExtensionsTests.cs`:

```csharp
using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Whois.Net;
using Whois.Servers;
using Xunit;

namespace Whois
{
    public class WhoisServiceCollectionExtensionsTests
    {
        [Fact]
        public void AddWhois_RegistersServices()
        {
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddWhois();
            var provider = services.BuildServiceProvider();

            Assert.NotNull(provider.GetService<IWhoisLookup>());
            Assert.NotNull(provider.GetService<ITcpReader>());
            Assert.NotNull(provider.GetService<IWhoisServerLookup>());
        }

        [Fact]
        public void AddWhois_WithConfigure_SetsOptions()
        {
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddWhois(options =>
            {
                options.TimeoutSeconds = 30;
                options.FollowReferrer = false;
            });
            var provider = services.BuildServiceProvider();

            var options = provider.GetRequiredService<IOptions<WhoisOptions>>();
            Assert.Equal(30, options.Value.TimeoutSeconds);
            Assert.False(options.Value.FollowReferrer);
        }
    }
}
```

- [ ] **Step 6: Add Microsoft.Extensions.DependencyInjection to test project**

Add to `Directory.Packages.props`:
```xml
<PackageVersion Include="Microsoft.Extensions.DependencyInjection" Version="9.0.0" />
<PackageVersion Include="Microsoft.Extensions.Logging" Version="9.0.0" />
```

Add to `tests/Whois.Tests/Whois.Tests.csproj`:
```xml
<PackageReference Include="Microsoft.Extensions.DependencyInjection" />
<PackageReference Include="Microsoft.Extensions.Logging" />
```

- [ ] **Step 7: Build and test**

Run: `dotnet build Whois.sln && dotnet test tests/Whois.Tests/Whois.Tests.csproj`
Expected: Build succeeds, all tests pass

- [ ] **Step 8: Commit**

```bash
git add Directory.Packages.props src/Whois/Whois.csproj src/Whois/WhoisServiceCollectionExtensions.cs src/Whois/WhoisLookup.cs src/Whois/Servers/IanaServerLookup.cs tests/Whois.Tests/
git commit -m "Add DI extension method and Options pattern support"
```

---

## Phase 5: Console App + Metadata + Docs

### Task 24: Modernize console app

**Files:**
- Modify: `tools/Whois.Console/Whois.Console.csproj`
- Modify: `tools/Whois.Console/Program.cs`
- Modify: `Directory.Packages.props`

- [ ] **Step 1: Update console csproj**

Remove:
```xml
<PackageReference Include="Newtonsoft.Json" />
<PackageReference Include="Serilog" />
<PackageReference Include="Serilog.Sinks.Console" />
<PackageReference Include="Serilog.Sinks.RollingFile" />
```

Remove the broken HintPath reference block:
```xml
<ItemGroup>
    <Reference Include="Newtonsoft.Json">
      <HintPath>..\..\..\..\Program Files\dotnet\sdk\NuGetFallbackFolder\newtonsoft.json\9.0.1\lib\netstandard1.0\Newtonsoft.Json.dll</HintPath>
    </Reference>
</ItemGroup>
```

Add:
```xml
<PackageReference Include="Microsoft.Extensions.Logging.Console" />
```

Add to `Directory.Packages.props`:
```xml
<PackageVersion Include="Microsoft.Extensions.Logging.Console" Version="9.0.0" />
```

- [ ] **Step 2: Update Program.cs**

Replace Serilog with M.E.Logging and Newtonsoft.Json with System.Text.Json:

```csharp
using System;
using System.Text.Json;
using System.Threading.Tasks;
using CommandLine;
using Microsoft.Extensions.Logging;

namespace Whois
{
    class Program
    {
        static async Task Main(string[] args)
        {
            await Parser.Default.ParseArguments<Options>(args)
                .WithParsedAsync(RunLookup);
        }

        private static async Task RunLookup(Options options)
        {
            using var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
                builder.SetMinimumLevel(LogLevel.Error);
            });

            var logger = loggerFactory.CreateLogger<WhoisLookup>();
            var lookup = new WhoisLookup(logger);

            var response = await lookup.Lookup(options.DomainName);

            if (options.OutputAsJson)
            {
                var json = JsonSerializer.Serialize(response, new JsonSerializerOptions { WriteIndented = true });
                Console.WriteLine(json);
            }
            else
            {
                Console.WriteLine(response.Content);
            }
        }
    }
}
```

Adjust the `Options` class to match the existing CLI argument structure (keep `CommandLineParser`).

- [ ] **Step 3: Clean up Directory.Packages.props**

Remove packages no longer used by any project:
```xml
<!-- Remove if console was the last consumer -->
<PackageVersion Include="Newtonsoft.Json" Version="13.0.2" />
<PackageVersion Include="Serilog" Version="2.12.0" />
<PackageVersion Include="Serilog.Sinks.Console" Version="4.1.0" />
<PackageVersion Include="Serilog.Sinks.RollingFile" Version="3.3.0" />
```

The integration test `SampleReader.cs` uses `JsonConvert.DeserializeObject` from Newtonsoft.Json. Migrate it to `System.Text.Json.JsonSerializer.Deserialize` and then remove `Newtonsoft.Json` from both the integration test csproj and `Directory.Packages.props`.

- [ ] **Step 4: Build the console app**

Run: `dotnet build tools/Whois.Console/Whois.Console.csproj`
Expected: Build succeeds

- [ ] **Step 5: Commit**

```bash
git add tools/Whois.Console/ Directory.Packages.props
git commit -m "Modernize console app: STJ, M.E.Logging, remove broken HintPath"
```

### Task 25: Update package metadata

**Files:**
- Modify: `src/Whois/Whois.csproj`

- [ ] **Step 1: Update metadata in Whois.csproj**

Update the package properties:

```xml
<PropertyGroup>
    <Version>4.0.0</Version>
    <Description>.NET library for querying and parsing WHOIS domain registration data. Targets .NET Standard 2.0, .NET 8, and .NET 10.</Description>
    <PackageReadmeFile>README.md</PackageReadmeFile>
    <PackageLicenseExpression>MIT</PackageLicenseExpression>
</PropertyGroup>

<ItemGroup>
    <None Include="..\..\README.md" Pack="true" PackagePath="\" />
</ItemGroup>
```

Remove the old license file packaging if present:
```xml
<!-- Remove these -->
<None Include="..\..\LICENSE.txt" Pack="true" PackagePath="" />
```

Note: Verify the license is MIT by checking LICENSE.txt. If it's a different license, use the correct SPDX identifier.

- [ ] **Step 2: Build to verify**

Run: `dotnet build src/Whois/Whois.csproj`
Expected: Build succeeds

- [ ] **Step 3: Commit**

```bash
git add src/Whois/Whois.csproj
git commit -m "Update package metadata: v4.0.0, description, SPDX license, README"
```

### Task 26: Refresh README.md

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Read the current README.md**

- [ ] **Step 2: Update README.md**

Update to reflect v4.0 changes:
- Updated targets (`.NET Standard 2.0 / .NET 8 / .NET 10`)
- Async-only API examples (no sync `Lookup()`)
- `CancellationToken` usage example
- DI setup with `AddWhois()` and Options pattern
- `ILogger` integration
- Remove any references to `.NET Framework 4.5.2`
- Update NuGet badge version

Keep the existing structure and tone. Don't rewrite from scratch — update what changed.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "Update README for v4.0: async-only API, DI, logging, new targets"
```

### Task 27: Create CHANGELOG.md

**Files:**
- Create: `CHANGELOG.md`

- [ ] **Step 1: Gather git history**

Run: `git log --oneline --all --reverse`
Use this to backfill historical releases.

- [ ] **Step 2: Create CHANGELOG.md**

Write a changelog following [Keep a Changelog](https://keepachangelog.com/) format. Include:

- **v4.0.0** (current) — all breaking changes, new features, removals
  - Breaking: async-only API, dropped `net452`, removed sync `Lookup()` methods
  - Breaking: `IWhoisLookup`, `ITcpReader`, `IWhoisServerLookup` no longer extend `IDisposable`
  - Breaking: `LookupAsync` renamed to `Lookup` (no Async suffix)
  - Breaking: `WhoisOptions.Defaults` removed, use `new WhoisOptions()` or Options pattern
  - Added: `CancellationToken` support on all async methods
  - Added: `Microsoft.Extensions.Logging` integration
  - Added: DI support via `AddWhois()` extension method
  - Added: Options pattern (`IOptions<WhoisOptions>`)
  - Added: Nullable reference type annotations
  - Added: `net8.0` and `net10.0` target frameworks
  - Changed: `TcpReader` is now stateless (no `IDisposable`)
  - Changed: Test framework migrated from NUnit/Moq to xUnit/NSubstitute
  - Removed: `AsyncHelper` (sync-over-async hack)
  - Removed: `LibLog` dependency (replaced with M.E.Logging)
  - Removed: `Microsoft.CSharp` dependency
  - Removed: `Newtonsoft.Json` from console app (replaced with System.Text.Json)

- **v3.0.1** and earlier — backfill from git history with dates and summaries

- [ ] **Step 3: Commit**

```bash
git add CHANGELOG.md
git commit -m "Add CHANGELOG.md backfilled from git history"
```

### Task 28: Update Whois.sln solution items

**Files:**
- Modify: `Whois.sln`

- [ ] **Step 1: Update Solution Items**

The `Solution Items` section currently references `appveyor.yml` (deleted) and `README.md`. Update to include the new files:

```
ProjectSection(SolutionItems) = preProject
    README.md = README.md
    CHANGELOG.md = CHANGELOG.md
    Directory.Build.props = Directory.Build.props
    Directory.Packages.props = Directory.Packages.props
    .editorconfig = .editorconfig
EndProjectSection
```

- [ ] **Step 2: Build to verify**

Run: `dotnet build Whois.sln`
Expected: Build succeeds

- [ ] **Step 3: Commit**

```bash
git add Whois.sln
git commit -m "Update solution items: add new build/config files"
```

### Task 29: Final integration verification

- [ ] **Step 1: Clean build**

Run: `dotnet clean Whois.sln && dotnet build Whois.sln`
Expected: Build succeeds with zero warnings

- [ ] **Step 2: Run all unit tests on both TFMs**

Run: `dotnet test tests/Whois.Tests/Whois.Tests.csproj --verbosity normal`
Expected: All tests pass on both net8.0 and net10.0

- [ ] **Step 3: Verify integration tests compile**

Run: `dotnet build tests/Whois.Tests.Integration/Whois.Tests.Integration.csproj`
Expected: Build succeeds

- [ ] **Step 4: Verify console app runs**

Run: `dotnet run --project tools/Whois.Console/Whois.Console.csproj -- google.com`
Expected: WHOIS response output

- [ ] **Step 5: Verify NuGet package builds**

Run: `dotnet pack src/Whois/Whois.csproj -c Release`
Expected: Package created with correct version, targets, and metadata

- [ ] **Step 6: Commit any final fixes**

```bash
git add -A
git commit -m "Final v4.0 verification and cleanup"
```
