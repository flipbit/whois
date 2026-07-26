using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Sn.Sn;

public class SnParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public SnParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.sn", "sn", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.sn", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        AssertWriter.Write(response);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.sn", "sn", "found", "google.sn.txt");
        var response = parser.Parse("whois.nic.sn", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/05", response.TemplateName);

        Assert.Null(response.DomainName);

        // Registrar Details
        Assert.Null(response.Registrar);

        Assert.Null(response.Registered);

        // Registrant Details
        Assert.Null(response.Registrant);


        // AdminContact Details
        Assert.Null(response.AdminContact);


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        Assert.Equal(5, response.FieldsParsed);
    }
}
