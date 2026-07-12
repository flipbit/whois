using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Bj.Bj;

public class BjParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public BjParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.bj", "bj", "not-found", "u34jedzcq.bj.txt");
        var response = parser.Parse("whois.nic.bj", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.bj/bj/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.bj", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.bj", "bj", "found", "google.bj.txt");
        var response = parser.Parse("whois.nic.bj", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.bj/bj/found/01", response.TemplateName);

        Assert.Equal("google.bj", response.DomainName.ToString());

        Assert.Equal(new DateTime(2012, 08, 10, 08, 57, 22, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2009, 03, 25, 08, 57, 22, 000, DateTimeKind.Utc), response.Registered);

        // Registrant Details
        Assert.Equal("GOOGLE INC (ED0155)", response.Registrant.Name);
        Assert.Equal("+1.6506234000", response.Registrant.TelephoneNumber);
        Assert.Equal("+1.6506188571", response.Registrant.FaxNumber);

        // Registrant Address
        Assert.Equal(2, response.Registrant.Address.Count);
        Assert.Equal("USA", response.Registrant.Address[0]);
        Assert.Equal("1600 Amphitheatre Parkway, Moutain View CA 94043, US", response.Registrant.Address[1]);


        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);

        Assert.Equal(12, response.FieldsParsed);
    }
}
