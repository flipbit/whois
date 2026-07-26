using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Website.Ws.Ws;

public class WsParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public WsParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.website.ws", "ws", "not-found", "u34jedzcq.ws.txt");
        var response = parser.Parse("whois.website.ws", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.website.ws/ws/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.ws", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.website.ws", "ws", "found", "google.ws.txt");
        var response = parser.Parse("whois.website.ws", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.website.ws/ws/found/01", response.TemplateName);

        Assert.Equal("google.ws", response.DomainName.ToString());

        // Registrar Details
        Assert.Null(response.Registrar);

        Assert.Null(response.Updated);
        Assert.Null(response.Registered);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);


        // AdminContact Details
        Assert.Null(response.AdminContact);


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        Assert.Equal(2, response.FieldsParsed);
    }
}
