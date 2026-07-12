using WhoisRefresh.Infrastructure;

namespace WhoisRefresh.Domain;

public class DriftDetector
{
    private readonly IDriftReporter _reporter;
    private readonly IFileSystem _fileSystem;

    public DriftDetector(IDriftReporter reporter, IFileSystem fileSystem)
    {
        _reporter = reporter;
        _fileSystem = fileSystem;
    }

    public async Task<List<DriftEntry>> DetectAsync(
        RefreshResults current,
        string repoRoot,
        string toolDirectoryRelative,
        CancellationToken cancellationToken)
    {
        // Read baseline from HEAD commit so that a freshly-written refresh-results.json
        // does not shadow the previous run's data.
        var repoRelativePath = $"{toolDirectoryRelative}/refresh-results.json".Replace('\\', '/');
        var baselineJson = await _fileSystem.GitReadHeadAsync(repoRoot, repoRelativePath, cancellationToken);

        RefreshResults baseline;
        if (baselineJson != null)
        {
            baseline = RefreshResults.Deserialize(baselineJson);
        }
        else
        {
            baseline = new RefreshResults { Version = DateTimeOffset.MinValue, Results = new() };
        }

        var entries = DriftClassifier.Classify(baseline, current);

        var hasBreakages = entries.Any(e => e.Severity == DriftSeverity.Breakage);

        if (hasBreakages)
        {
            var markdown = DriftReportGenerator.ToMarkdown(entries);
            await _reporter.ReportAsync(entries, markdown, repoRoot, cancellationToken);
        }

        return entries;
    }
}
