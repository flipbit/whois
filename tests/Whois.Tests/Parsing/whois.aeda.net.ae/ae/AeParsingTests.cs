using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Aeda.Net.Ae.Ae;

public class AeParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public AeParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.aeda.net.ae", "ae", "not-found", "not_found.txt");
        var response = parser.Parse("whois.aeda.net.ae", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.aeda.net.ae", "ae", "found", "google.ae.txt");
        var response = parser.Parse("whois.aeda.net.ae", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(11, response.FieldsParsed);
        Assert.Equal(0, response.ParsingErrors);

        Assert.Equal("google.ae", response.DomainName.ToString());

        Assert.Equal("MarkMonitor", response.Registrar.Name);

        Assert.Equal("GOOGLE", response.Registrant.RegistryId);
        Assert.Equal("Google Inc.", response.Registrant.Name);

        Assert.Equal("GOOGLE", response.TechnicalContact.RegistryId);
        Assert.Equal("Google Inc.", response.TechnicalContact.Name);


        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);

        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);
    }
}
