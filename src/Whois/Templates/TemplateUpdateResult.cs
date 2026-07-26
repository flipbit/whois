namespace Whois.Templates;

/// <summary>
/// Result of a template update attempt.
/// </summary>
public sealed record TemplateUpdateResult(
    TemplateUpdateOutcome Outcome,
    string? Version,
    string? Error);
