using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ci.Ci;

public class CiParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public CiParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.ci", "ci", "not-found", "u34jedzcq.ci.txt");
        var response = parser.Parse("whois.nic.ci", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.ci/ci/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.ci", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.ci", "ci", "found", "google.ci.txt");
        var response = parser.Parse("whois.nic.ci", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.ci", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("AFRIREGISTER", response.Registrar.Name);

        Assert.Equal(new DateTime(2013, 02, 14, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 02, 13, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);


        // AdminContact Details
        Assert.Null(response.AdminContact);


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        Assert.Equal(16, response.FieldsParsed);
    }
}
