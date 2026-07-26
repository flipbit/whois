namespace Whois.Protocols;

/// <summary>
/// Internal mutable contact type for Tokenizer template compatibility.
/// Mapped to the public <see cref="Whois.Contact"/> by <see cref="WhoisRecordMapper"/>.
/// </summary>
internal sealed class WhoisContact
{
    public WhoisContact()
    {
        Address = new List<string>();
    }

    public string? RegistryId { get; set; }
    public string? Name { get; set; }
    public string? Organization { get; set; }
    public IList<string> Address { get; }
    public string? TelephoneNumber { get; set; }
    public string? TelephoneNumberExt { get; set; }
    public string? FaxNumber { get; set; }
    public string? FaxNumberExt { get; set; }
    public string? Email { get; set; }
    public DateTime? Created { get; set; }
    public DateTime? Updated { get; set; }
}
