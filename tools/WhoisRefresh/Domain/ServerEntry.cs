namespace WhoisRefresh.Domain;

public record ServerEntry(
    string Tld,
    bool IsStatic,
    string? RateGroup,
    Dictionary<string, List<string>> Domains);
