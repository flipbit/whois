using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Sh.Sh;

public class ShParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public ShParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.sh", "sh", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.sh", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        AssertWriter.Write(response);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.sh", "sh", "found", "found.txt");
        var response = parser.Parse("whois.nic.sh", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.sh/sh/found/01", response.TemplateName);

        Assert.Equal("google.sh", response.DomainName.ToString());

        Assert.Equal(new DateTime(2014, 06, 06, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("DNS Admin", response.Registrant.Name);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("Google Inc.", response.Registrant.Address[0]);
        Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[1]);
        Assert.Equal("Mountain View", response.Registrant.Address[2]);
        Assert.Equal("CA", response.Registrant.Address[3]);
        Assert.Equal("US", response.Registrant.Address[4]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Live", response.DomainStatus[0]);

        Assert.Equal(12, response.FieldsParsed);
    }
}
