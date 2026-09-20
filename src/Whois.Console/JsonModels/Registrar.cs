using System.Text.Json.Serialization;

namespace Whois.JsonModels;

public class Registrar
{
    public Registrar(Whois.Registrar registrar)
    {
        Name = registrar.Name;
        IanaId = registrar.IanaId;
        Url = registrar.Url;
        AbuseEmail = registrar.AbuseEmail;
        AbuseTelephoneNumber = registrar.AbuseTelephoneNumber;
        WhoisServer = registrar.WhoisServer;
    }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Name { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IanaId { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Url { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AbuseEmail { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AbuseTelephoneNumber { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public HostName? WhoisServer { get; set; }
}
