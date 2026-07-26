using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Registry.Qa.Qa;

public class QaParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public QaParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.registry.qa", "qa", "found", "qnb.com.qa.txt");
        var response = parser.Parse("whois.registry.qa", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.registry.qa/qa/found/01", response.TemplateName);

        Assert.Equal("qnb.com.qa", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Ooredoo QSC", response.Registrar.Name);

        // Registrant Details
        Assert.Null(response.Registrant);


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("brenna.ns.cloudflare.com", response.NameServers[0]);
        Assert.Equal("emerson.ns.cloudflare.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal(6, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.registry.qa", "qa", "not-found", "not_found.txt");
        var response = parser.Parse("whois.registry.qa", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.registry.qa/qa/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.registry.qa", "qa", "found", "qtel.com.qa.txt");
        var response = parser.Parse("whois.registry.qa", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.registry.qa/qa/found/01", response.TemplateName);

        Assert.Equal("qtel.com.qa", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Ooredoo QSC", response.Registrar.Name);


        // Registrant Details
        Assert.Null(response.Registrant);


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);


        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("dns2.qatar.net.qa", response.NameServers[0]);
        Assert.Equal("dns1.qatar.net.qa", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal(7, response.FieldsParsed);
    }
}
