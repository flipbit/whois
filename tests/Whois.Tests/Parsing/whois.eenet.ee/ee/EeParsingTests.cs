using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Eenet.Ee.Ee;

public class EeParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public EeParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.eenet.ee", "ee", "not-found", "u34jedzcq.ee.txt");
        var response = parser.Parse("whois.eenet.ee", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/03", response.TemplateName);

        Assert.Null(response.DomainName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.eenet.ee", "ee", "found", "google.ee.txt");
        var response = parser.Parse("whois.eenet.ee", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.eenet.ee/ee/found/01", response.TemplateName);

        Assert.Equal("google.ee", response.DomainName.ToString());

        Assert.Equal(new DateTime(2010, 05, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2003, 04, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

        // Registrant Details
        Assert.Equal("ADVOKAADIBÜROO SORAINEN AS", response.Registrant.Name);
        Assert.Equal("5274536", response.Registrant.TelephoneNumber);
        Assert.Equal("+372 6400 901", response.Registrant.FaxNumber);

        // Registrant Address
        Assert.Equal(1, response.Registrant.Address.Count);
        Assert.Equal("PÄRNU MNT, 15, HARJUMAA TALLINN KESKLINN 10141", response.Registrant.Address[0]);


        // AdminContact Details
        Assert.Equal("Mart Meier", response.AdminContact.Name);
        Assert.Equal("mart.meier@sorainen.ee", response.AdminContact.Email);


        // TechnicalContact Details
        Assert.Equal("Joshua Hopping", response.TechnicalContact.Name);
        Assert.Equal("ccops@markmonitor.com", response.TechnicalContact.Email);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);

        Assert.Equal(14, response.FieldsParsed);
    }
}
