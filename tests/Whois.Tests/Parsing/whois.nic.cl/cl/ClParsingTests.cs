using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Cl.Cl;

public class ClParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public ClParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.cl", "cl", "not-found", "u34jedzcq.cl.txt");
        var response = parser.Parse("whois.nic.cl", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.cl/cl/not-found/02", response.TemplateName);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.cl", "cl", "found", "google.cl.txt");
        var response = parser.Parse("whois.nic.cl", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.cl/cl/found/02", response.TemplateName);

        Assert.Equal("google.cl", response.DomainName.ToString());

        // Registrant Details
        Assert.Equal("Google LLC", response.Registrant.Name);

        // Registrar Details
        Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);

        Assert.Equal(new DateTime(2002, 10, 22, 0, 0, 0, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2026, 11, 20, 0, 0, 0, DateTimeKind.Utc), response.Expiration);

        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);
    }
}
