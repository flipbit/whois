namespace Whois.Templates;

/// <summary>
/// Describes what happened during a template update attempt.
/// </summary>
public enum TemplateUpdateOutcome
{
    Updated,
    AlreadyUpToDate,
    Failed,
    Skipped,
}
