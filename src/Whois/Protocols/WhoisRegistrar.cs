namespace Whois.Protocols;

/// <summary>
/// Internal mutable registrar type for Tokenizer template compatibility.
/// Mapped to the public <see cref="Whois.Registrar"/> by <see cref="WhoisRecordMapper"/>.
/// </summary>
internal sealed class WhoisRegistrar
{
    public string? Name { get; set; }
    public string? IanaId { get; set; }
    public string? Url { get; set; }
    public string? AbuseEmail { get; set; }
    public string? AbuseTelephoneNumber { get; set; }
    public HostName? WhoisServer { get; set; }
}
