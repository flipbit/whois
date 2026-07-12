using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ac.Ac;

public class AcParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public AcParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.ac", "ac", "not-found", "u34jedzcq.ac.txt");
        var response = parser.Parse("whois.nic.ac", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.ac/ac/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.ac", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.ac", "ac", "found", "google.ac.txt");
        var response = parser.Parse("whois.nic.ac", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.ac/ac/found/01", response.TemplateName);

        Assert.Equal("google.ac", response.DomainName.ToString());

        Assert.Equal(new DateTime(2014, 04, 03, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("DNS Admin", response.Registrant.Name);
        Assert.Equal("Google Inc.", response.Registrant.Organization);

        // Registrant Address
        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
        Assert.Equal("Mountain View", response.Registrant.Address[1]);
        Assert.Equal("CA", response.Registrant.Address[2]);
        Assert.Equal("US", response.Registrant.Address[3]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Live", response.DomainStatus[0]);

        Assert.Equal(14, response.FieldsParsed);
    }
}
