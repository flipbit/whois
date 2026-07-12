using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Mg.Mg;

public class MgParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public MgParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.mg", "mg", "not-found", "u34jedzcq.mg.txt");
        var response = parser.Parse("whois.nic.mg", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/04", response.TemplateName);

        Assert.Equal("u34jedzcq.mg", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.mg", "mg", "found", "google.mg.txt");
        var response = parser.Parse("whois.nic.mg", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.mg", response.DomainName.ToString());
        Assert.Equal("1915-nicmg", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);
        Assert.Null(response.Registrar.Url);
        Assert.Null(response.Registrar.AbuseEmail);
        Assert.Null(response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2025, 10, 27, 17, 49, 22, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2009, 06, 18, 08, 38, 20, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2026, 11, 26, 21, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(5, response.DomainStatus.Count);
        Assert.Equal("active", response.DomainStatus[0]);
        Assert.Equal("clientRenewProhibited", response.DomainStatus[1]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[2]);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[3]);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[4]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(18, response.FieldsParsed);
    }
}
