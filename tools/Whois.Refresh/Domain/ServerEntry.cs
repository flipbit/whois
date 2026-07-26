namespace Whois.Refresh.Domain;

public record ServerEntry(
    string Tld,
    bool IsStatic,
    string? RateGroup,
    IDictionary<string, IList<string>> Domains);
