using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Me.Me;

public class MeParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public MeParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.me", "me", "found", "wossna.me.txt");
        var response = parser.Parse("whois.nic.me", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("wossna.me", response.DomainName.ToString());
        Assert.Equal("D82062-ME", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("Gandi SAS R114-ME (81)", response.Registrar.Name);

        Assert.Equal(new DateTime(2010, 08, 16, 02, 15, 52, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2008, 07, 17, 15, 54, 20, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2011, 07, 17, 15, 54, 20, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("GM937-GANDI", response.Registrant.RegistryId);
        Assert.Equal("Graeme Mathieson", response.Registrant.Name);
        Assert.Equal("+44.7949077744", response.Registrant.TelephoneNumber);
        Assert.Equal("mathie@rubaidh.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("12d Monktonhall Terrace", response.Registrant.Address[0]);
        Assert.Equal("Musselburgh", response.Registrant.Address[1]);
        Assert.Equal("EH21 6ER", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("GM2519-GANDI", response.AdminContact.RegistryId);
        Assert.Equal("Graeme Mathieson", response.AdminContact.Name);
        Assert.Equal("Rubaidh Ltd", response.AdminContact.Organization);
        Assert.Equal("+44.1312735271", response.AdminContact.TelephoneNumber);
        Assert.Equal("support@rubaidh.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("Stuart House", response.AdminContact.Address[0]);
        Assert.Equal("Eskmills", response.AdminContact.Address[1]);
        Assert.Equal("Musselburgh", response.AdminContact.Address[2]);
        Assert.Equal("EH21 7PB", response.AdminContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("GM2519-GANDI", response.TechnicalContact.RegistryId);
        Assert.Equal("Graeme Mathieson", response.TechnicalContact.Name);
        Assert.Equal("Rubaidh Ltd", response.TechnicalContact.Organization);
        Assert.Equal("+44.1312735271", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("support@rubaidh.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(4, response.TechnicalContact.Address.Count);
        Assert.Equal("Stuart House", response.TechnicalContact.Address[0]);
        Assert.Equal("Eskmills", response.TechnicalContact.Address[1]);
        Assert.Equal("Musselburgh", response.TechnicalContact.Address[2]);
        Assert.Equal("EH21 7PB", response.TechnicalContact.Address[3]);


        // Domain Status
        Assert.Equal(3, response.DomainStatus.Count);
        Assert.Equal("CLIENT TRANSFER PROHIBITED", response.DomainStatus[0]);
        Assert.Equal("INACTIVE", response.DomainStatus[1]);
        Assert.Equal("PENDING DELETE", response.DomainStatus[2]);

        Assert.Equal(36, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_updated_on_is_blank()
    {
        var sample = SampleReader.Read("whois.nic.me", "me", "found", "factoryoutlet.me.txt");
        var response = parser.Parse("whois.nic.me", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("factoryoutlet.me", response.DomainName.ToString());
        Assert.Equal("REDACTED", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("Dominet (HK) Limited", response.Registrar.Name);

        Assert.Equal(new DateTime(2026, 06, 25, 13, 17, 32, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 06, 25, 13, 17, 32, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("REDACTED", response.Registrant.RegistryId);
        Assert.Equal("REDACTED", response.Registrant.Name);
        Assert.Null(response.Registrant.TelephoneNumber);
        Assert.Null(response.Registrant.FaxNumber);
        Assert.Null(response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("REDACTED", response.Registrant.Address[0]);
        Assert.Equal("REDACTED", response.Registrant.Address[1]);
        Assert.Equal("Jiangsu", response.Registrant.Address[2]);
        Assert.Equal("REDACTED", response.Registrant.Address[3]);


        // AdminContact Details
        Assert.Equal("REDACTED", response.AdminContact.RegistryId);
        Assert.Equal("REDACTED", response.AdminContact.Name);
        Assert.Equal("REDACTED", response.AdminContact.Organization);
        Assert.Null(response.AdminContact.TelephoneNumber);
        Assert.Null(response.AdminContact.FaxNumber);
        Assert.Null(response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("REDACTED", response.AdminContact.Address[0]);
        Assert.Equal("REDACTED", response.AdminContact.Address[1]);
        Assert.Equal("REDACTED", response.AdminContact.Address[2]);
        Assert.Equal("REDACTED", response.AdminContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("REDACTED", response.TechnicalContact.RegistryId);
        Assert.Equal("REDACTED", response.TechnicalContact.Name);
        Assert.Equal("REDACTED", response.TechnicalContact.Organization);
        Assert.Null(response.TechnicalContact.TelephoneNumber);
        Assert.Null(response.TechnicalContact.FaxNumber);
        Assert.Null(response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("REDACTED", response.TechnicalContact.Address[0]);
        Assert.Equal("REDACTED", response.TechnicalContact.Address[1]);
        Assert.Equal("REDACTED", response.TechnicalContact.Address[2]);
        Assert.Equal("REDACTED", response.TechnicalContact.Address[3]);


        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal(40, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.me", "me", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.me", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.nic.me", "me", "found", "google.me.txt");
        var response = parser.Parse("whois.nic.me", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.me", response.DomainName.ToString());
        Assert.Equal("REDACTED", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);

        Assert.Equal(new DateTime(2026, 05, 17, 10, 34, 16, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2008, 06, 13, 17, 17, 40, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 06, 13, 17, 17, 40, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("REDACTED", response.Registrant.RegistryId);
        Assert.Equal("REDACTED", response.Registrant.Name);
        Assert.Equal("Google LLC", response.Registrant.Organization);
        Assert.Null(response.Registrant.TelephoneNumber);
        Assert.Null(response.Registrant.FaxNumber);
        Assert.Null(response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("REDACTED", response.Registrant.Address[0]);
        Assert.Equal("REDACTED", response.Registrant.Address[1]);
        Assert.Equal("CA", response.Registrant.Address[2]);
        Assert.Equal("REDACTED", response.Registrant.Address[3]);


        // AdminContact Details
        Assert.Equal("REDACTED", response.AdminContact.RegistryId);
        Assert.Equal("REDACTED", response.AdminContact.Name);
        Assert.Equal("REDACTED", response.AdminContact.Organization);
        Assert.Null(response.AdminContact.TelephoneNumber);
        Assert.Null(response.AdminContact.FaxNumber);
        Assert.Null(response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("REDACTED", response.AdminContact.Address[0]);
        Assert.Equal("REDACTED", response.AdminContact.Address[1]);
        Assert.Equal("REDACTED", response.AdminContact.Address[2]);
        Assert.Equal("REDACTED", response.AdminContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("REDACTED", response.TechnicalContact.RegistryId);
        Assert.Equal("REDACTED", response.TechnicalContact.Name);
        Assert.Equal("REDACTED", response.TechnicalContact.Organization);
        Assert.Null(response.TechnicalContact.TelephoneNumber);
        Assert.Null(response.TechnicalContact.FaxNumber);
        Assert.Null(response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("REDACTED", response.TechnicalContact.Address[0]);
        Assert.Equal("REDACTED", response.TechnicalContact.Address[1]);
        Assert.Equal("REDACTED", response.TechnicalContact.Address[2]);
        Assert.Equal("REDACTED", response.TechnicalContact.Address[3]);


        // Domain Status
        Assert.Equal(6, response.DomainStatus.Count);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
        Assert.Equal("serverDeleteProhibited", response.DomainStatus[1]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[2]);
        Assert.Equal("serverTransferProhibited", response.DomainStatus[3]);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[4]);
        Assert.Equal("serverUpdateProhibited", response.DomainStatus[5]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(47, response.FieldsParsed);
    }
}
