using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Uniregistry.Net.Tattoo;

public class TattooParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public TattooParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.uniregistry.net", "tattoo", "not-found", "not_found.txt");
        var response = parser.Parse("whois.uniregistry.net", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.uniregistry.net/tattoo/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.tattoo", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.uniregistry.net", "tattoo", "found", "nic.tattoo.txt");
        var response = parser.Parse("whois.uniregistry.net", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/02", response.TemplateName);

        Assert.Equal("nic.tattoo", response.DomainName.ToString());
        Assert.Null(response.RegistryDomainId);

        // Registrar Details
        Assert.Null(response.Registrar);

        Assert.Null(response.Updated);
        Assert.Null(response.Registered);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // BillingContact Details
        Assert.Null(response.BillingContact);

        // BillingContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(0, response.DomainStatus.Count);

        Assert.Null(response.DnsSecStatus);
        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_unavailable()
    {
        var sample = SampleReader.Read("whois.uniregistry.net", "tattoo", "unavailable", "unavailable.txt");
        var response = parser.Parse("whois.uniregistry.net", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Unavailable, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.uniregistry.net/tattoo/unavailable/01", response.TemplateName);

        Assert.Equal("cheap.tattoo", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }
}
