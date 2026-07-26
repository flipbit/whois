using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Tm.Tm;

public class TmParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public TmParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.tm", "tm", "not-found", "u34jedzcq.tm.txt");
        var response = parser.Parse("whois.nic.tm", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.tm/tm/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.tm", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.tm", "tm", "found", "google.tm.txt");
        var response = parser.Parse("whois.nic.tm", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.tm/tm/found/01", response.TemplateName);

        Assert.Equal("google.tm", response.DomainName.ToString());

        // Registrant Details
        Assert.Equal("DNS Admin", response.Registrant.Name);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("Google Inc.", response.Registrant.Address[0]);
        Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[1]);
        Assert.Equal("Mountain View", response.Registrant.Address[2]);
        Assert.Equal("CA", response.Registrant.Address[3]);
        Assert.Equal("US", response.Registrant.Address[4]);


        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Client Updt Lock", response.DomainStatus[0]);

        Assert.Equal(9, response.FieldsParsed);
    }
}
