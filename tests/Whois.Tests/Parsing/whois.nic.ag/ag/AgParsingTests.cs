using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ag.Ag;

public class AgParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public AgParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.ag", "ag", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.ag", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.ag", "ag", "found", "google.ag.txt");
        var response = parser.Parse("whois.nic.ag", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.ag", response.DomainName.ToString());
        Assert.Equal("REDACTED", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);

        Assert.Equal(new DateTime(2025, 12, 09, 10, 44, 54, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2003, 01, 05, 14, 06, 59, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 01, 05, 14, 06, 59, 000, DateTimeKind.Utc), response.Expiration);

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


        // BillingContact Details
        Assert.Null(response.BillingContact);

        // BillingContact Address


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
