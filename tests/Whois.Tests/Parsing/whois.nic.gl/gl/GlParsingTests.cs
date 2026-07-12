using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Gl.Gl;

public class GlParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public GlParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.gl", "gl", "not-found", "u34jedzcq.gl.txt");
        var response = parser.Parse("whois.nic.gl", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/01", response.TemplateName);

        Assert.Null(response.DomainName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.gl", "gl", "found", "google.gl.txt");
        var response = parser.Parse("whois.nic.gl", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/02", response.TemplateName);

        Assert.Equal("google.gl", response.DomainName.ToString());
        Assert.Equal("D327730546-CNIC", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);
        Assert.Null(response.Registrar.Url);
        Assert.Equal("ccops@markmonitor.com", response.Registrar.AbuseEmail);

        Assert.Equal(new DateTime(2026, 01, 01, 16, 02, 36, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2003, 03, 11, 03, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 01, 01, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(3, response.DomainStatus.Count);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[1]);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[2]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(17, response.FieldsParsed);
    }
}
