using System.Diagnostics;
using WhoisRefresh.Domain;

namespace WhoisRefresh.Infrastructure;

public class GhCliDriftReporter : IDriftReporter
{
    public async Task ReportAsync(List<DriftEntry> entries, string markdownReport, CancellationToken cancellationToken)
    {
        var branch = "template-drift";

        if (await HasHumanCommitsAsync(branch, cancellationToken))
        {
            branch = $"template-drift/{DateTime.UtcNow:yyyy-MM-dd}";
        }

        // Create/update PR via gh CLI
        await RunGhAsync($"pr create --base main --head {branch} --title \"Template drift detected\" --body \"{EscapeForShell(markdownReport)}\"", cancellationToken);
    }

    public async Task<bool> HasHumanCommitsAsync(string branch, CancellationToken cancellationToken)
    {
        try
        {
            var result = await RunGhAsync($"api repos/{{owner}}/{{repo}}/compare/main...{branch} --jq '.ahead_by'", cancellationToken);
            return int.TryParse(result.Trim(), out var ahead) && ahead > 0;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<string> RunGhAsync(string arguments, CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo("gh", arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start gh process");

        var output = await process.StandardOutput.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);

        return output;
    }

    private static string EscapeForShell(string input)
    {
        return input.Replace("\"", "\\\"").Replace("\n", "\\n");
    }
}
