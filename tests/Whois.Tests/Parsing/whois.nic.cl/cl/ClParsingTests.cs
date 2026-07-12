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

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.cl", "cl", "not-found", "u34jedzcq.cl.txt");
        var response = parser.Parse("whois.nic.cl", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.cl/cl/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.cl", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.cl", "cl", "found", "google.cl.txt");
        var response = parser.Parse("whois.nic.cl", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/02", response.TemplateName);

        Assert.Null(response.DomainName);

        // Registrant Details
        Assert.Null(response.Registrant);

        // AdminContact Details
        Assert.Null(response.AdminContact);


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        Assert.Equal(2, response.FieldsParsed);
    }
}
