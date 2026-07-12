using System.Text.Json;

namespace WhoisMigration;

public class MigrateCommand
{
    public record MigrationResult(
        int TemplatesMoved,
        int SamplesMoved,
        int TemplatesFrontMatterUpdated,
        List<string> Errors,
        Dictionary<string, string> TemplateNameMap);

    public static MigrationResult Execute(string repoRoot, bool dryRun = false)
    {
        var errors = new List<string>();
        var templateNameMap = new Dictionary<string, string>();
        var templatesMoved = 0;
        var samplesMoved = 0;
        var frontMatterUpdated = 0;

        // --- Migrate templates ---
        var resourcesDir = Path.Combine(repoRoot, "src", "Whois", "Resources");
        templatesMoved = MigrateTemplates(resourcesDir, dryRun, errors, templateNameMap);
        frontMatterUpdated = templatesMoved;

        // --- Migrate samples ---
        var samplesDir = Path.Combine(repoRoot, "tests", "Whois.Tests", "Samples");
        samplesMoved = MigrateSamples(samplesDir, dryRun, errors);

        return new MigrationResult(templatesMoved, samplesMoved, frontMatterUpdated, errors, templateNameMap);
    }

    public static void SaveTemplateNameMap(Dictionary<string, string> map, string outputPath)
    {
        var json = JsonSerializer.Serialize(map, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(outputPath, json);
    }

    public static Dictionary<string, string> LoadTemplateNameMap(string path)
    {
        var json = File.ReadAllText(path);
        return JsonSerializer.Deserialize<Dictionary<string, string>>(json)
               ?? throw new InvalidOperationException("Failed to deserialize template name map.");
    }

    private static int MigrateTemplates(string resourcesDir, bool dryRun, List<string> errors, Dictionary<string, string> templateNameMap)
    {
        var moved = 0;

        // Migrate server/tld-level templates (the normal two-level structure)
        foreach (var tldDir in EnumerateTldDirectories(resourcesDir))
        {
            var serverName = Path.GetFileName(Path.GetDirectoryName(tldDir)!);
            var tldName = Path.GetFileName(tldDir);
            moved += MigrateTemplateDirectory(tldDir, $"{serverName}/{tldName}", dryRun, errors, templateNameMap);
        }

        // Migrate server-level templates (e.g. whois.iana.org/Found01.txt with no tld subdir)
        foreach (var serverDir in Directory.GetDirectories(resourcesDir))
        {
            var serverName = Path.GetFileName(serverDir);
            var serverLevelFiles = Directory.GetFiles(serverDir, "*.txt");
            if (serverLevelFiles.Length > 0)
            {
                moved += MigrateTemplateDirectory(serverDir, serverName, dryRun, errors, templateNameMap);
            }
        }

        return moved;
    }

    private static int MigrateTemplateDirectory(
        string templateDir,
        string namePrefix,
        bool dryRun,
        List<string> errors,
        Dictionary<string, string> templateNameMap)
    {
        var moved = 0;
        var templateFiles = Directory.GetFiles(templateDir, "*.txt");

        if (templateFiles.Length == 0) return 0;

        // Group by status (extracted from front matter)
        var groups = new Dictionary<string, List<(string OldPath, string OldName)>>();
        foreach (var filePath in templateFiles)
        {
            var content = File.ReadAllText(filePath);
            var oldName = Path.GetFileNameWithoutExtension(filePath);
            try
            {
                var status = TemplateMapper.ExtractStatus(content);
                var statusDir = TemplateMapper.ToStatusDirectory(status);
                if (!groups.ContainsKey(statusDir))
                    groups[statusDir] = [];
                groups[statusDir].Add((filePath, oldName));
            }
            catch (InvalidOperationException ex)
            {
                errors.Add($"Template {filePath}: {ex.Message}");
            }
        }

        // Assign numbers and move files
        foreach (var (statusDir, files) in groups)
        {
            var oldNames = files.Select(f => f.OldName).ToList();
            var numberMap = TemplateMapper.AssignNumbers(oldNames);

            var targetDir = Path.Combine(templateDir, statusDir);
            if (!dryRun) Directory.CreateDirectory(targetDir);

            foreach (var (oldPath, oldName) in files)
            {
                var number = numberMap[oldName];
                var newPath = Path.Combine(targetDir, $"{number}.txt");
                var newFrontMatterName = $"{namePrefix}/{statusDir}/{number}";

                var oldFrontMatterName = $"{namePrefix}/{oldName}";
                templateNameMap[oldFrontMatterName] = newFrontMatterName;

                if (!dryRun)
                {
                    var content = File.ReadAllText(oldPath);
                    var updatedContent = TemplateMapper.UpdateFrontMatterName(
                        content, newFrontMatterName);
                    File.WriteAllText(newPath, updatedContent);
                    File.Delete(oldPath);
                }

                moved++;
            }
        }

        return moved;
    }

    private static int MigrateSamples(string samplesDir, bool dryRun, List<string> errors)
    {
        var moved = 0;

        foreach (var tldDir in EnumerateTldDirectories(samplesDir))
        {
            var sampleFiles = Directory.GetFiles(tldDir, "*.txt");

            foreach (var filePath in sampleFiles)
            {
                var filename = Path.GetFileName(filePath);
                try
                {
                    var (status, _) = SampleMapper.MapToStatusDirectory(filename);
                    var targetDir = Path.Combine(tldDir, status);
                    var newPath = Path.Combine(targetDir, filename);

                    if (!dryRun)
                    {
                        Directory.CreateDirectory(targetDir);
                        File.Move(filePath, newPath);
                    }

                    moved++;
                }
                catch (InvalidOperationException ex)
                {
                    errors.Add($"Sample {filePath}: {ex.Message}");
                }
            }
        }

        return moved;
    }

    /// <summary>
    /// Enumerates directories at the {server}/{tld} level.
    /// Resources and Samples both use this two-level structure.
    /// </summary>
    private static IEnumerable<string> EnumerateTldDirectories(string rootDir)
    {
        foreach (var serverDir in Directory.GetDirectories(rootDir))
        {
            foreach (var tldDir in Directory.GetDirectories(serverDir))
            {
                yield return tldDir;
            }
        }
    }
}
