using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dotmobiregistry.Net.Mobi;

public class MobiParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public MobiParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.dotmobiregistry.net", "mobi", "not-found", "not_found.txt");
        var response = parser.Parse("whois.dotmobiregistry.net", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.dotmobiregistry.net", "mobi", "found", "google.mobi.txt");
        var response = parser.Parse("whois.dotmobiregistry.net", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.mobi", response.DomainName.ToString());
        Assert.Equal("c42565101c784c69b0ed90239ad6044c-DONUTS", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);

        Assert.Equal(new DateTime(2024, 04, 14, 10, 13, 05, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2006, 05, 11, 21, 08, 42, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2025, 05, 11, 21, 08, 42, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.RegistryId);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Name);
        Assert.Equal("Google LLC", response.Registrant.Organization);
        Assert.Null(response.Registrant.TelephoneNumber);
        Assert.Null(response.Registrant.FaxNumber);
        Assert.Null(response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Address[0]);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Address[1]);
        Assert.Equal("CA", response.Registrant.Address[2]);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Address[3]);
        Assert.Equal("US", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.RegistryId);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Name);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Organization);
        Assert.Null(response.AdminContact.TelephoneNumber);
        Assert.Null(response.AdminContact.FaxNumber);
        Assert.Null(response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Address[0]);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Address[1]);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Address[2]);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Address[3]);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.RegistryId);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Name);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Organization);
        Assert.Null(response.TechnicalContact.TelephoneNumber);
        Assert.Null(response.TechnicalContact.FaxNumber);
        Assert.Null(response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[0]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[1]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[2]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[3]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns4.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns2.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(3, response.DomainStatus.Count);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[1]);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[2]);

        Assert.Equal(44, response.FieldsParsed);
    }
}
