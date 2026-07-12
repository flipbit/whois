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
        DomainRegistryData registry,
        string toolDirectory,
        CancellationToken cancellationToken)
    {
        var baselinePath = Path.Combine(toolDirectory, "refresh-results.json");

        RefreshResults baseline;
        if (_fileSystem.FileExists(baselinePath))
        {
            var baselineJson = await _fileSystem.ReadAllTextAsync(baselinePath, cancellationToken);
            baseline = RefreshResults.Deserialize(baselineJson);
        }
        else
        {
            baseline = new RefreshResults { Version = DateTimeOffset.MinValue, Results = new() };
        }

        var entries = DriftClassifier.Classify(baseline, current, registry);

        var hasBreakages = entries.Any(e => e.Severity == DriftSeverity.Breakage);

        if (hasBreakages)
        {
            var markdown = DriftReportGenerator.ToMarkdown(entries);
            await _reporter.ReportAsync(entries, markdown, cancellationToken);
        }

        return entries;
    }
}
