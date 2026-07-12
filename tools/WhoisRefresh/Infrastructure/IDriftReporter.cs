using WhoisRefresh.Domain;

namespace WhoisRefresh.Infrastructure;

public interface IDriftReporter
{
    Task ReportAsync(List<DriftEntry> entries, string markdownReport, string repoRoot, CancellationToken cancellationToken);
    Task<bool> HasHumanCommitsAsync(string branch, CancellationToken cancellationToken);
}
