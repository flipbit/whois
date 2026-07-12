using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Registry.Om.Om;

public class OmParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public OmParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.registry.om", "om", "not-found", "not_found.txt");
        var response = parser.Parse("whois.registry.om", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.registry.om/om/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.registry.om", "om", "found", "rop.gov.om.txt");
        var response = parser.Parse("whois.registry.om", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("rop.gov.om", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Oman Telecommunication Company (Omantel)", response.Registrar.Name);

        Assert.Null(response.Updated);

        // Registrant Details
        Assert.Null(response.Registrant.RegistryId);
        Assert.Equal("Ahmed  Al Khanbashi", response.Registrant.Name);

        // Registrant Address
        Assert.Equal(0, response.Registrant.Address.Count);


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns4.ict.omantel.om", response.NameServers[0]);
        Assert.Equal("ns3.ict.omantel.om", response.NameServers[1]);

        // Domain Status
        Assert.Equal(0, response.DomainStatus.Count);

        Assert.Equal(12, response.FieldsParsed);
    }

    [Fact]
    public void Test_reserved()
    {
        var sample = SampleReader.Read("whois.registry.om", "om", "reserved", "reserved.txt");
        var response = parser.Parse("whois.registry.om", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Reserved, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.registry.om/om/reserved/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }
}
