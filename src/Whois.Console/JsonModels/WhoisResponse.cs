using System.Text.Json.Serialization;

namespace Whois.JsonModels;

public class WhoisResponse
{
    public WhoisResponse()
    {
    }

    public WhoisResponse(DomainInfo info)
    {
        DomainName = info.DomainName?.ToString();
        RegistryDomainId = info.RegistryDomainId;
        Registered = info.Registered;
        Updated = info.Updated;
        Expiration = info.Expiration;
        if (info.Registrant != null) Registrant = new Contact(info.Registrant);
        if (info.TechnicalContact != null) TechnicalContact = new Contact(info.TechnicalContact);
        if (info.AdminContact != null) AdminContact = new Contact(info.AdminContact);
        if (info.Registrar != null) Registrar = new Registrar(info.Registrar);
        if (info.NameServers.Count > 0) NameServers = info.NameServers;
        if (info.DomainStatus.Count > 0) DomainStatus = info.DomainStatus;
        DnsSecStatus = info.DnsSecStatus;
    }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DomainName { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RegistryDomainId { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTime? Registered { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTime? Updated { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTime? Expiration { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Registrar? Registrar { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Contact? Registrant { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Contact? TechnicalContact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Contact? AdminContact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? NameServers { get; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? DomainStatus { get; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DnsSecStatus { get; set; }
}
