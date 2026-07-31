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

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.bj", "bj", "not-found", "u34jedzcq.bj.txt");
        var response = parser.Parse("whois.nic.bj", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/04", response.TemplateName);

        Assert.Equal("u34jedzcq.bj", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.bj", "bj", "found", "google.bj.txt");
        var response = parser.Parse("whois.nic.bj", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.bj", response.DomainName.ToString());

        Assert.Equal(new DateTime(2025, 12, 28, 15, 41, 24, 764, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2015, 01, 29, 11, 16, 22, 808, DateTimeKind.Utc), response.Registered);

        // Registrant Details
        Assert.Equal("Domain Administrator", response.Registrant.Name);
        Assert.Equal("+1.6502530000", response.Registrant.TelephoneNumber);
        Assert.Equal("+1.6502530001", response.Registrant.FaxNumber);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
        Assert.Equal("Mountain View", response.Registrant.Address[1]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);

        Assert.Equal(52, response.FieldsParsed);
    }
}
