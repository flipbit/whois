using WhoisRefresh.Domain;

namespace WhoisRefresh.Infrastructure;

public interface IDriftReporter
{
    public Task ReportAsync(List<DriftEntry> entries, string markdownReport, string repoRoot, CancellationToken cancellationToken);
    public Task<bool> HasHumanCommitsAsync(string branch, CancellationToken cancellationToken);
}
