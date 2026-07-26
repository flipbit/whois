using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Xyz.Xyz;

public class XyzParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public XyzParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.xyz", "xyz", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.xyz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.xyz", "xyz", "found", "abc.xyz.txt");
        var response = parser.Parse("whois.nic.xyz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/02", response.TemplateName);

        Assert.Equal("abc.xyz", response.DomainName.ToString());
        Assert.Equal("D2192285-CNIC", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);
        Assert.Equal("292", response.Registrar.IanaId);
        Assert.Null(response.Registrar.Url);
        Assert.Equal("whois.markmonitor.com", response.Registrar.WhoisServer.Value);

        Assert.Equal(new DateTime(2026, 03, 06, 12, 00, 40, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2014, 03, 20, 12, 59, 17, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 03, 20, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

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
        Assert.Equal("ns2.google.com", response.NameServers[0]);
        Assert.Equal("ns4.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns1.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(3, response.DomainStatus.Count);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[1]);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[2]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(19, response.FieldsParsed);
    }
}
