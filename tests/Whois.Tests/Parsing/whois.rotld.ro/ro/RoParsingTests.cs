using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Rotld.Ro.Ro;

public class RoParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public RoParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_other_status_updateprohibited()
    {
        var sample = SampleReader.Read("whois.rotld.ro", "ro", "found", "other_status_updateprohibited.txt");
        var response = parser.Parse("whois.rotld.ro", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.rotld.ro/ro/found/01", response.TemplateName);

        Assert.Equal("google.ro", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);

        Assert.Equal(new DateTime(2000, 07, 17, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns4.google.com", response.NameServers[0]);
        Assert.Equal("ns1.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns2.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("UpdateProhibited", response.DomainStatus[0]);

        Assert.Equal(9, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.rotld.ro", "ro", "not-found", "not_found.txt");
        var response = parser.Parse("whois.rotld.ro", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.rotld.ro/ro/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.rotld.ro", "ro", "found", "found.txt");
        var response = parser.Parse("whois.rotld.ro", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.rotld.ro/ro/found/01", response.TemplateName);

        Assert.Equal("google.ro", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);
        Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);

        Assert.Equal(new DateTime(2000, 07, 17, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("UpdateProhibited", response.DomainStatus[0]);

        Assert.Equal(10, response.FieldsParsed);
    }
}
