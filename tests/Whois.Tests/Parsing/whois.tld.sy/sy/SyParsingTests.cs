using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Tld.Sy.Sy;

public class SyParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public SyParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.tld.sy", "sy", "not-found", "u34jedzcq.sy.txt");
        var response = parser.Parse("whois.tld.sy", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/04", response.TemplateName);

        Assert.Equal("u34jedzcq.sy", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.tld.sy", "sy", "found", "tld.sy.txt");
        var response = parser.Parse("whois.tld.sy", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("tld.sy", response.DomainName.ToString());
        Assert.Equal("7-sy", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("?????? ??????? ?????? ????? ?????????", response.Registrar.Name);

        Assert.Equal(new DateTime(2010, 12, 02, 16, 01, 27, 664, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2055, 12, 30, 22, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant.RegistryId);
        Assert.Equal("domain@tld.sy", response.Registrant.Email);


        // BillingContact Details
        Assert.Null(response.BillingContact.RegistryId);
        Assert.Equal("domain@tld.sy", response.BillingContact.Email);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns4.tld.sy", response.NameServers[0]);
        Assert.Equal("ns3.tld.sy", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(12, response.FieldsParsed);
    }
}
