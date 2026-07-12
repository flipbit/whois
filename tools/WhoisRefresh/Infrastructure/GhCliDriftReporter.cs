using System.Diagnostics;
using WhoisRefresh.Domain;

namespace WhoisRefresh.Infrastructure;

public class GhCliDriftReporter : IDriftReporter
{
    public async Task ReportAsync(List<DriftEntry> entries, string markdownReport, string repoRoot, CancellationToken cancellationToken)
    {
        var branch = "template-drift";

        if (await HasHumanCommitsAsync(branch, cancellationToken))
        {
            branch = $"template-drift/{DateTime.UtcNow:yyyy-MM-dd}";
        }

        await CommitAndPushAsync(branch, repoRoot, cancellationToken);
        await CreateOrUpdatePrAsync(branch, markdownReport, cancellationToken);
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

    private static async Task CommitAndPushAsync(string branch, string repoRoot, CancellationToken cancellationToken)
    {
        // Checkout (or create) the branch
        await RunGitAsync($"checkout -B {branch}", repoRoot, cancellationToken);

        // Stage the files updated by the refresh/detect workflow
        await RunGitAsync("add tools/WhoisRefresh/refresh-results.json", repoRoot, cancellationToken);
        await RunGitAsync("add tools/WhoisRefresh/drift-report.json tools/WhoisRefresh/drift-report.md", repoRoot, cancellationToken);

        await RunGitAsync("commit -m \"chore: update template drift results\"", repoRoot, cancellationToken);
        await RunGitAsync($"push --force-with-lease origin {branch}", repoRoot, cancellationToken);
    }

    private static async Task CreateOrUpdatePrAsync(string branch, string markdownReport, CancellationToken cancellationToken)
    {
        var existingPrNumber = await FindExistingPrAsync(branch, cancellationToken);

        if (existingPrNumber.HasValue)
        {
            await RunGhAsync(
                $"pr edit {existingPrNumber} --body \"{EscapeForShell(markdownReport)}\"",
                cancellationToken);
        }
        else
        {
            await RunGhAsync(
                $"pr create --base main --head {branch} --title \"Template drift detected\" --body \"{EscapeForShell(markdownReport)}\"",
                cancellationToken);
        }
    }

    private static async Task<int?> FindExistingPrAsync(string branch, CancellationToken cancellationToken)
    {
        try
        {
            var result = await RunGhAsync(
                $"pr list --head {branch} --state open --json number --jq '.[0].number'",
                cancellationToken);

            var trimmed = result.Trim();
            return int.TryParse(trimmed, out var number) ? number : null;
        }
        catch
        {
            return null;
        }
    }

    private static async Task<string> RunGitAsync(string arguments, string workingDirectory, CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo("git", arguments)
        {
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start git process");

        var output = await process.StandardOutput.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);

        return output;
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
