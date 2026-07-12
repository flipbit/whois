namespace Whois.Templates;

/// <summary>
/// Reports the current state of the template cache.
/// </summary>
public sealed record TemplateStatus(
    string CurrentVersion,
    TemplateSource Source,
    DateTimeOffset? LastCheckTime,
    DateTimeOffset? NextCheckTime,
    string? LastError,
    bool AutoUpdateEnabled);
