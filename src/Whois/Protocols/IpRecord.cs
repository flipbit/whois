namespace Whois.Protocols;

/// <summary>
/// Internal mutable record type that Tokenizer's Assign populates from WHOIS IP templates.
/// Mapped to public <see cref="IpInfo"/> by <see cref="WhoisRecordMapper"/>.
/// </summary>
internal sealed class IpRecord
{
    public string? Network { get; set; }
    public string? Cidr { get; set; }
    public string? NetName { get; set; }
    public string? Organization { get; set; }
    public string? Country { get; set; }
    public RegistrationStatus Status { get; set; }
    public DateTime? Registered { get; set; }
    public DateTime? Updated { get; set; }
    public string? Remarks { get; set; }

    // Diagnostics
    public string Content { get; set; } = string.Empty;
    public int FieldsParsed { get; set; }
    public int ParsingErrors { get; set; }
    public string? TemplateName { get; set; }
}
