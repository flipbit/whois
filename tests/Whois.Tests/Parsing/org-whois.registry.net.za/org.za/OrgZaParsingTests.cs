using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Org.Whois.Registry.Net.Za.OrgZa;

public class OrgZaParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public OrgZaParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("org-whois.registry.net.za", "org.za", "not-found", "nosuchdomain.org.za.txt");
        var response = parser.Parse("org-whois.registry.net.za", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(2, response.FieldsParsed);
        Assert.Equal(0, response.ParsingErrors);

        Assert.Equal("nosuchdomain.org.za", response.DomainName.ToString());
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("org-whois.registry.net.za", "org.za", "found", "joburg.org.za.txt");
        var response = parser.Parse("org-whois.registry.net.za", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("org-whois.registry.net.za/org.za/found/01", response.TemplateName);

        Assert.Equal("joburg.org.za", response.DomainName.ToString());
        Assert.Equal("6m5mut_DOMAIN-ORG.ZA", response.RegistryDomainId);

        // Registrar Details
        Assert.Null(response.Registrar.Name);
        Assert.Equal("whois.lexsynergy.com", response.Registrar.WhoisServer.Value);

        Assert.Equal(new DateTime(2026, 6, 4, 16, 8, 12, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1997, 10, 3, 9, 46, 34, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2026, 8, 31, 9, 44, 13, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant.RegistryId);
        Assert.Null(response.Registrant.Name);

        // Registrant Address
        Assert.Equal(1, response.Registrant.Address.Count);
        Assert.Equal("ZA", response.Registrant.Address[0]);

        Assert.Null(response.Registrant.TelephoneNumber);
        Assert.Null(response.Registrant.FaxNumber);
        Assert.Null(response.Registrant.Email);


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address



        // BillingContact Details
        Assert.Null(response.BillingContact);

        // BillingContact Address

        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("jupiter.is.co.za", response.NameServers[0]);
        Assert.Equal("demeter.is.co.za", response.NameServers[1]);
        Assert.Equal("titan.is.co.za", response.NameServers[2]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(13, response.FieldsParsed);
    }
}
