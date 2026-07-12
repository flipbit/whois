namespace Whois.Templates;

/// <summary>
/// Downloads, verifies, and caches template packs from a remote release URL.
/// </summary>
public interface ITemplatePackProvider
{
    /// <summary>
    /// Gets the current state of the template cache and auto-update mechanism.
    /// </summary>
    public TemplateStatus Status { get; }

    /// <summary>
    /// Checks for a newer template pack, downloads and installs it if available.
    /// Never throws — returns <see cref="TemplateUpdateOutcome.Failed"/> on any error.
    /// Serialises concurrent calls — the second caller gets <see cref="TemplateUpdateOutcome.Skipped"/>.
    /// </summary>
    public Task<TemplateUpdateResult> CheckForUpdate(CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns the directory path for a server's cached templates,
    /// or <see langword="null"/> if no cache exists for that server.
    /// </summary>
    public string? GetCachedTemplatePath(string server);
}
