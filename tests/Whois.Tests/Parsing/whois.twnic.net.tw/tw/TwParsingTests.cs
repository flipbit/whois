using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Twnic.Net.Tw.Tw;

public class TwParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public TwParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.twnic.net.tw", "tw", "not-found", "not_found.txt");
        var response = parser.Parse("whois.twnic.net.tw", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.twnic.net.tw/tw/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.twnic.net.tw", "tw", "found", "google.com.tw.txt");
        var response = parser.Parse("whois.twnic.net.tw", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.twnic.net.tw/tw/found/01", response.TemplateName);

        Assert.Equal("google.com.tw", response.DomainName.ToString());

        // Registrar Details
        Assert.Null(response.Registrar);

        Assert.Null(response.Registered);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        Assert.Equal(2, response.FieldsParsed);
    }
}
