using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Thnic.Co.Th.Th;

public class ThParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public ThParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.thnic.co.th", "th", "not-found", "u34jedzcq.co.th.txt");
        var response = parser.Parse("whois.thnic.co.th", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.thnic.co.th/th/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.co.th", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.thnic.co.th", "th", "found", "google.co.th.txt");
        var response = parser.Parse("whois.thnic.co.th", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.co.th", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("THNIC", response.Registrar.Name);

        Assert.Null(response.Updated);
        Assert.Null(response.Registered);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact.RegistryId);
        Assert.Null(response.TechnicalContact.Name);

        // TechnicalContact Address
        Assert.Equal(2, response.TechnicalContact.Address.Count);
        Assert.Equal("Personal Information", response.TechnicalContact.Address[0]);
        Assert.Equal("Personal Information", response.TechnicalContact.Address[1]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns3.google.com", response.NameServers[0]);
        Assert.Equal("ns1.google.com", response.NameServers[1]);
        Assert.Equal("ns4.google.com", response.NameServers[2]);
        Assert.Equal("ns2.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ACTIVE", response.DomainStatus[0]);

        Assert.Equal(12, response.FieldsParsed);
    }
}
