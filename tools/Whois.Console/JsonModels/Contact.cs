using System.Text.Json.Serialization;

namespace Whois.JsonModels;

public class Contact
{
    public Contact()
    {
    }

    public Contact(Whois.Contact contact)
    {
        RegistryId = contact.RegistryId;
        Name = contact.Name;
        Organization = contact.Organization;
        Address = contact.Address?.Lines;
        TelephoneNumber = contact.TelephoneNumber;
        TelephoneNumberExt = contact.TelephoneNumberExt;
        FaxNumber = contact.FaxNumber;
        FaxNumberExt = contact.FaxNumberExt;
        Email = contact.Email;
    }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RegistryId { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Name { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Organization { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? Address { get; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TelephoneNumber { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TelephoneNumberExt { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? FaxNumber { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? FaxNumberExt { get; set; }
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Email { get; set; }
}
