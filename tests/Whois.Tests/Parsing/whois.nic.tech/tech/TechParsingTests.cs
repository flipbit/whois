using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Tech.Tech;

public class TechParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public TechParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.tech", "tech", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.tech", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.tech", "tech", "found", "google.tech.txt");
        var response = parser.Parse("whois.nic.tech", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/02", response.TemplateName);

        Assert.Equal("google.tech", response.DomainName.ToString());
        Assert.Equal("D9157622-CNIC", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);
        Assert.Equal("292", response.Registrar.IanaId);
        Assert.Equal("https://www.markmonitor.com/", response.Registrar.Url);
        Assert.Equal("whois.markmonitor.com", response.Registrar.WhoisServer.Value);

        Assert.Equal(new DateTime(2026, 07, 02, 10, 17, 07, 969, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2015, 07, 29, 14, 20, 05, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 07, 29, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


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
        Assert.Equal(3, response.DomainStatus.Count);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[1]);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[2]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(20, response.FieldsParsed);
    }
}
