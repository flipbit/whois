namespace Whois.Protocols;

/// <summary>
/// Internal mutable record type that Tokenizer's Assign&lt;T&gt;() populates from WHOIS templates.
/// Mirrors the old WhoisResponse structure for template compatibility.
/// Mapped to public <see cref="DomainInfo"/> + <see cref="LookupDiagnostics"/> by <see cref="WhoisRecordMapper"/>.
/// </summary>
internal sealed class WhoisRecord
{
    public WhoisRecord()
    {
        Content = string.Empty;
        NameServers = new List<string>();
        DomainStatus = new List<string>();
    }

    // Domain data
    public HostName? DomainName { get; set; }
    public string? RegistryDomainId { get; set; }
    public RegistrationStatus Status { get; set; }
    public IList<string> DomainStatus { get; }
    public DateTime? Registered { get; set; }
    public DateTime? Updated { get; set; }
    public DateTime? Expiration { get; set; }
    public WhoisRegistrar? Registrar { get; set; }
    public WhoisContact? Registrant { get; set; }
    public WhoisContact? TechnicalContact { get; set; }
    public WhoisContact? AdminContact { get; set; }
    public WhoisContact? BillingContact { get; set; }
    public WhoisContact? ZoneContact { get; set; }
    public IList<string> NameServers { get; }
    public string? Remarks { get; set; }
    public string? DnsSecStatus { get; set; }
    public Trademark? Trademark { get; set; }

    // Diagnostics
    public string Content { get; set; }
    public int ContentLength => string.IsNullOrEmpty(Content) ? 0 : Content.Length;
    public int FieldsParsed { get; set; }
    public int ParsingErrors { get; set; }
    public string? TemplateName { get; set; }

    // Referral tracking (used by WhoisProtocolClient)
    public HostName? WhoisServer => Registrar?.WhoisServer;
}
