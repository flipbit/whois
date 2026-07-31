using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Je.Je;

public class JeParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public JeParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.je", "je", "not-found", "u34jedzcq.je.txt");
        var response = parser.Parse("whois.je", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/01", response.TemplateName);

        Assert.Null(response.DomainName);

        // Domain Status
        Assert.Equal(0, response.DomainStatus.Count);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.je", "je", "found", "google.je.txt");
        var response = parser.Parse("whois.je", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.je/je/found/01", response.TemplateName);

        Assert.Equal("google.je", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);
        Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);

        Assert.Equal(new DateTime(2002, 10, 31, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

        // Registrant Details
        Assert.Equal("Google Inc.", response.Registrant.Name);
        Assert.Equal("Google Inc.", response.Registrant.Organization);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns4.google.com", response.NameServers[2]);
        Assert.Equal("ns3.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Active", response.DomainStatus[0]);

        Assert.Equal(12, response.FieldsParsed);
    }
}
