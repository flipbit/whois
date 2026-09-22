using System.Text.Json.Serialization;

namespace Whois.JsonModels;

/// <summary>
/// JSON serialization model for IP address registration information.
/// </summary>
public class IpResponse
{
    /// <summary>
    /// Initializes a new instance of the <see cref="IpResponse"/> class.
    /// </summary>
    public IpResponse()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="IpResponse"/> class from IP registration information.
    /// </summary>
    /// <param name="info">The IP registration information.</param>
    public IpResponse(IpInfo info)
    {
        Network = info.Network;
        Cidr = info.Cidr;
        NetName = info.NetName;
        Organization = info.Organization;
        Country = info.Country;
        Rir = info.Rir;
        Registered = info.Registered;
        Updated = info.Updated;
        Remarks = info.Remarks;
        if (info.AbuseContact != null) AbuseContact = new Contact(info.AbuseContact);
        if (info.AdminContact != null) AdminContact = new Contact(info.AdminContact);
        if (info.TechnicalContact != null) TechnicalContact = new Contact(info.TechnicalContact);
    }

    /// <summary>
    /// Network address.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Network { get; set; }

    /// <summary>
    /// CIDR notation.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Cidr { get; set; }

    /// <summary>
    /// Network name.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? NetName { get; set; }

    /// <summary>
    /// Organization name.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Organization { get; set; }

    /// <summary>
    /// Country code.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Country { get; set; }

    /// <summary>
    /// Regional Internet Registry.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Rir { get; set; }

    /// <summary>
    /// Registration date.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTime? Registered { get; set; }

    /// <summary>
    /// Last update date.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTime? Updated { get; set; }

    /// <summary>
    /// Remarks or additional information.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Remarks { get; set; }

    /// <summary>
    /// Abuse contact information.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Contact? AbuseContact { get; set; }

    /// <summary>
    /// Administrative contact information.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Contact? AdminContact { get; set; }

    /// <summary>
    /// Technical contact information.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Contact? TechnicalContact { get; set; }
}
