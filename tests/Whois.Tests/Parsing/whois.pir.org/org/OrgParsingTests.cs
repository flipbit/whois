using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Pir.Org.Org;

public class OrgParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public OrgParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_throttled()
    {
        var sample = SampleReader.Read("whois.pir.org", "org", "throttled", "throttled.txt");
        var response = parser.Parse("whois.pir.org", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Throttled, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/throttled/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.pir.org", "org", "not-found", "not_found.txt");
        var response = parser.Parse("whois.pir.org", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.pir.org", "org", "found", "google.org.txt");
        var response = parser.Parse("whois.pir.org", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/02", response.TemplateName);

        Assert.Equal("google.org", response.DomainName.ToString());
        Assert.Equal("REDACTED", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);
        Assert.Equal("292", response.Registrar.IanaId);

        Assert.Equal(new DateTime(2025, 09, 23, 10, 18, 47, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1998, 10, 21, 04, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2026, 10, 20, 04, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

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
        Assert.Equal(6, response.DomainStatus.Count);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
        Assert.Equal("serverDeleteProhibited", response.DomainStatus[1]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[2]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(23, response.FieldsParsed);
    }
}
