using WhoisMigration;

if (args.Length < 1)
{
    Console.WriteLine("Usage: WhoisMigration <repo-root> [--dry-run] [update-tests]");
    return 1;
}

var repoRoot = args[0];
var dryRun = args.Contains("--dry-run");
var updateTests = args.Contains("update-tests");
var templateMapPath = Path.Combine(repoRoot, "tools", "WhoisMigration", "template-name-map.json");

if (updateTests)
{
    Console.WriteLine("Updating parsing tests...");

    IDictionary<string, string> templateNameMap;
    if (File.Exists(templateMapPath))
    {
        Console.WriteLine($"Loading template name map from: {templateMapPath}");
        templateNameMap = MigrateCommand.LoadTemplateNameMap(templateMapPath);
    }
    else
    {
        Console.WriteLine("No saved template name map found. Re-running migration in dry-run mode to build map...");
        var migResult = MigrateCommand.Execute(repoRoot, dryRun: true);
        templateNameMap = migResult.TemplateNameMap;
    }

    var parsingTestsDir = Path.Combine(repoRoot, "tests", "Whois.Tests", "Parsing");
    var testFiles = Directory.GetFiles(parsingTestsDir, "*ParsingTests.cs", SearchOption.AllDirectories);
    var updatedCount = 0;

    foreach (var testFile in testFiles)
    {
        var content = File.ReadAllText(testFile);
        var updated = TestUpdater.UpdateSampleReaderCalls(content);
        updated = TestUpdater.UpdateTemplateNameAssertions(updated, templateNameMap);

        if (!string.Equals(content, updated, StringComparison.Ordinal))
        {
            if (!dryRun) File.WriteAllText(testFile, updated);
            Console.WriteLine($"  Updated: {Path.GetRelativePath(repoRoot, testFile)}");
            updatedCount++;
        }
    }

    Console.WriteLine(string.Format(System.Globalization.CultureInfo.InvariantCulture, "\nTest files updated: {0}", updatedCount));
    return 0;
}

Console.WriteLine($"Migrating: {repoRoot}");
Console.WriteLine($"Dry run: {dryRun}");

var result = MigrateCommand.Execute(repoRoot, dryRun);

Console.WriteLine(string.Format(System.Globalization.CultureInfo.InvariantCulture, "Templates moved: {0}", result.TemplatesMoved));
Console.WriteLine(string.Format(System.Globalization.CultureInfo.InvariantCulture, "Samples moved: {0}", result.SamplesMoved));
Console.WriteLine(string.Format(System.Globalization.CultureInfo.InvariantCulture, "Front matter updated: {0}", result.TemplatesFrontMatterUpdated));

if (result.Errors.Count > 0)
{
    Console.WriteLine(string.Format(System.Globalization.CultureInfo.InvariantCulture, "\nErrors ({0}):", result.Errors.Count));
    foreach (var error in result.Errors)
    {
        Console.WriteLine($"  - {error}");
    }
    return 1;
}

if (!dryRun)
{
    Console.WriteLine($"Saving template name map to: {templateMapPath}");
    MigrateCommand.SaveTemplateNameMap(result.TemplateNameMap, templateMapPath);
}

Console.WriteLine("\nMigration complete.");
return 0;
