using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Name.Name;

public class NameParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public NameParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_reserved()
    {
        var sample = SampleReader.Read("whois.nic.name", "name", "reserved", "reserved.txt");
        var response = parser.Parse("whois.nic.name", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Reserved, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.name/name/reserved/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.name", "name", "not-found", "u34jedzcq.name.txt");
        var response = parser.Parse("whois.nic.name", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/07", response.TemplateName);

        Assert.Equal("u34jedzcq.name", response.DomainName.ToString());
        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.name", "name", "found", "carletti.name.txt");
        var response = parser.Parse("whois.nic.name", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.name/name/found/01", response.TemplateName);

        Assert.Equal("carletti.name", response.DomainName.ToString());
        Assert.Null(response.RegistryDomainId);

        // Registrar Details
        Assert.Null(response.Registrar);

        Assert.Null(response.Updated);
        Assert.Null(response.Registered);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);


        // AdminContact Details
        Assert.Null(response.AdminContact);


        // BillingContact Details
        Assert.Null(response.BillingContact);


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);


        // Nameservers
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);

        Assert.Equal(3, response.FieldsParsed);
    }
}
