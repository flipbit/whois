using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Afilias.Grs.Info.Sc;

public class ScParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public ScParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.afilias-grs.info", "sc", "not-found", "not_found.txt");
        var response = parser.Parse("whois.afilias-grs.info", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(1, response.FieldsParsed);
        Assert.Equal("generic/tld/not-found/01", response.TemplateName);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.afilias-grs.info", "sc", "found", "google.sc.txt");
        var response = parser.Parse("whois.afilias-grs.info", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.sc", response.DomainName.ToString());
        Assert.Equal("REDACTED", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);

        Assert.Equal(new DateTime(2026, 01, 07, 10, 17, 54, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2004, 02, 03, 19, 19, 12, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 02, 03, 19, 19, 12, 000, DateTimeKind.Utc), response.Expiration);

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
        Assert.Equal("US", response.Registrant.Address[4]);


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
        Assert.Equal("REDACTED", response.AdminContact.Address[4]);


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
        Assert.Equal("REDACTED", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(3, response.DomainStatus.Count);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[1]);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[2]);

        Assert.Equal(42, response.FieldsParsed);
    }
}
