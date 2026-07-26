using System.Text.Json.Serialization;

namespace Whois.JsonModels;

public class WhoisResponse
{
    public WhoisResponse()
    {
    }

    public WhoisResponse(Whois.WhoisResponse response)
    {
        DomainName = response.DomainName?.ToString();
        RegistryDomainId = response.RegistryDomainId;
        Registered = response.Registered;
        Updated = response.Updated;
        Expiration = response.Expiration;
        if (response.Registrant != null) Registrant = new Contact(response.Registrant);
        if (response.TechnicalContact != null) TechnicalContact = new Contact(response.TechnicalContact);
        if (response.AdminContact != null) AdminContact = new Contact(response.AdminContact);
        if (response.Registrar != null) Registrar = new Registrar(response.Registrar);
        if (response.NameServers != null && response.NameServers.Any()) NameServers = response.NameServers;
        if (response.DomainStatus != null && response.DomainStatus.Any()) DomainStatus = response.DomainStatus;
        DnsSecStatus = response.DnsSecStatus;
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
    public IList<string>? NameServers { get; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IList<string>? DomainStatus { get; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DnsSecStatus { get; set; }
}
