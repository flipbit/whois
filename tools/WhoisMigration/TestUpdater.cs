using System.Text.RegularExpressions;

namespace WhoisMigration;

public static partial class TestUpdater
{
    [GeneratedRegex(
        @"SampleReader\.Read\(""([^""]+)"",\s*""([^""]+)"",\s*""([^""]+)""\)",
        RegexOptions.None)]
    private static partial Regex SampleReaderCallPattern();

    /// <summary>
    /// Updates SampleReader.Read calls to include the status parameter.
    /// </summary>
    public static string UpdateSampleReaderCalls(string testFileContent)
    {
        return SampleReaderCallPattern().Replace(testFileContent, match =>
        {
            var server = match.Groups[1].Value;
            var tld = match.Groups[2].Value;
            var filename = match.Groups[3].Value;

            var (status, _) = SampleMapper.MapToStatusDirectory(filename);

            return $"SampleReader.Read(\"{server}\", \"{tld}\", \"{status}\", \"{filename}\")";
        });
    }

    /// <summary>
    /// Updates TemplateName assertions to use new naming convention.
    /// Requires a mapping from old template names to new names,
    /// built during the template migration.
    /// </summary>
    public static string UpdateTemplateNameAssertions(
        string testFileContent,
        Dictionary<string, string> templateNameMap)
    {
        foreach (var (oldName, newName) in templateNameMap)
        {
            testFileContent = testFileContent.Replace(
                $"\"{oldName}\"",
                $"\"{newName}\"");
        }
        return testFileContent;
    }
}
