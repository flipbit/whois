using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Eu.Eu;

public class EuParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public EuParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.eu", "eu", "found", "eurid.eu.txt");
        var response = parser.Parse("whois.eu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.eu/eu/found/01", response.TemplateName);

        Assert.Equal("eurid.eu", response.DomainName.ToString());

        // Registrar Details
        Assert.Null(response.Registrar.Name);
        Assert.Equal("https://www.eurid.eu", response.Registrar.Url);

        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        Assert.Equal(3, response.FieldsParsed);
    }

    [Fact]
    public void Test_throttled()
    {
        var sample = SampleReader.Read("whois.eu", "eu", "throttled", "throttled.txt");
        var response = parser.Parse("whois.eu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Throttled, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.eu/eu/throttled/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.eu", "eu", "not-found", "u34jedzcq.eu.txt");
        var response = parser.Parse("whois.eu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.eu/eu/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.eu", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.eu", "eu", "found", "google.eu.txt");
        var response = parser.Parse("whois.eu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.eu/eu/found/01", response.TemplateName);

        Assert.Equal("google.eu", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("https://www.markmonitor.com/", response.Registrar.Url);

        Assert.Equal(3, response.FieldsParsed);
    }
}
