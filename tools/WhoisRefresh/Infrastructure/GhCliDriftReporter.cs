using System.Diagnostics;
using System.Globalization;
using WhoisRefresh.Domain;

namespace WhoisRefresh.Infrastructure;

public class GhCliDriftReporter : IDriftReporter
{
    public async Task ReportAsync(IList<DriftEntry> entries, string markdownReport, string repoRoot, CancellationToken cancellationToken)
    {
        var branch = "template-drift";

        if (await HasHumanCommitsAsync(branch, cancellationToken).ConfigureAwait(false))
        {
            branch = $"template-drift/{DateTime.UtcNow.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}";
        }

        await CommitAndPushAsync(branch, repoRoot, cancellationToken).ConfigureAwait(false);
        await CreateOrUpdatePrAsync(branch, markdownReport, cancellationToken).ConfigureAwait(false);
    }

    public async Task<bool> HasHumanCommitsAsync(string branch, CancellationToken cancellationToken)
    {
        try
        {
            var result = await RunGhAsync($"api repos/{{owner}}/{{repo}}/compare/main...{branch} --jq '.ahead_by'", cancellationToken).ConfigureAwait(false);
            return int.TryParse(result.Trim(), out var ahead) && ahead > 0;
        }
#pragma warning disable CA1031 // Catch-all: gh CLI may fail in many ways; treat any failure as no human commits
        catch
#pragma warning restore CA1031
        {
            return false;
        }
    }

    private static async Task CommitAndPushAsync(string branch, string repoRoot, CancellationToken cancellationToken)
    {
        // Checkout (or create) the branch
        await RunGitAsync($"checkout -B {branch}", repoRoot, cancellationToken).ConfigureAwait(false);

        // Stage the files updated by the refresh/detect workflow
        await RunGitAsync("add tools/WhoisRefresh/refresh-results.json", repoRoot, cancellationToken).ConfigureAwait(false);
        await RunGitAsync("add tools/WhoisRefresh/drift-report.json tools/WhoisRefresh/drift-report.md", repoRoot, cancellationToken).ConfigureAwait(false);

        await RunGitAsync("commit -m \"chore: update template drift results\"", repoRoot, cancellationToken).ConfigureAwait(false);
        await RunGitAsync($"push --force-with-lease origin {branch}", repoRoot, cancellationToken).ConfigureAwait(false);
    }

    private static async Task CreateOrUpdatePrAsync(string branch, string markdownReport, CancellationToken cancellationToken)
    {
        var existingPrNumber = await FindExistingPrAsync(branch, cancellationToken).ConfigureAwait(false);

        if (existingPrNumber.HasValue)
        {
            await RunGhAsync(
                string.Format(CultureInfo.InvariantCulture, "pr edit {0} --body \"{1}\"", existingPrNumber, EscapeForShell(markdownReport)),
                cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await RunGhAsync(
                $"pr create --base main --head {branch} --title \"Template drift detected\" --body \"{EscapeForShell(markdownReport)}\"",
                cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task<int?> FindExistingPrAsync(string branch, CancellationToken cancellationToken)
    {
        try
        {
            var result = await RunGhAsync(
                $"pr list --head {branch} --state open --json number --jq '.[0].number'",
                cancellationToken).ConfigureAwait(false);

            var trimmed = result.Trim();
            return int.TryParse(trimmed, out var number) ? number : null;
        }
#pragma warning disable CA1031 // Catch-all: gh CLI may fail in many ways; treat any failure as no existing PR
        catch
#pragma warning restore CA1031
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
            UseShellExecute = false,
        };

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start git process");

        var output = await process.StandardOutput.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

        return output;
    }

    private static async Task<string> RunGhAsync(string arguments, CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo("gh", arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start gh process");

        var output = await process.StandardOutput.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

        return output;
    }

    private static string EscapeForShell(string input)
    {
        return input.Replace("\"", "\\\"", StringComparison.Ordinal).Replace("\n", "\\n", StringComparison.Ordinal);
    }
}
