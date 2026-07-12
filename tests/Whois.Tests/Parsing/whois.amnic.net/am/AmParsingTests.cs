using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Amnic.Net.Am;

public class AmParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public AmParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.amnic.net", "am", "not-found", "not_found.txt");
        var response = parser.Parse("whois.amnic.net", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.amnic.net", "am", "found", "google.am.txt");
        var response = parser.Parse("whois.amnic.net", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(4, response.FieldsParsed);
        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.am", response.DomainName.ToString());
        Assert.Equal("abcdomain (ABCDomain LLC)", response.Registrar.Name);

        Assert.Null(response.Updated);
        Assert.Null(response.Registered);
        Assert.Null(response.Expiration);
        Assert.Null(response.Registrant);



        Assert.Null(response.AdminContact);



        Assert.Null(response.TechnicalContact);




        Assert.Equal(0, response.NameServers.Count);

        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("active, registrar locked", response.DomainStatus[0]);
    }
}
