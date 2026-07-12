using WhoisRefresh.Domain;

namespace WhoisRefresh.Infrastructure;

public interface IDriftReporter
{
    Task ReportAsync(List<DriftEntry> entries, string markdownReport, CancellationToken cancellationToken);
    Task<bool> HasHumanCommitsAsync(string branch, CancellationToken cancellationToken);
}
