using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Space.Space;

public class SpaceParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public SpaceParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.space", "space", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.space", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.space", "space", "found", "nic.space.txt");
        var response = parser.Parse("whois.nic.space", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/02", response.TemplateName);

        Assert.Equal("nic.space", response.DomainName.ToString());
        Assert.Equal("D2361836-CNIC", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("Radix Technologies Inc. SEZC / CO Services Cayman Limited", response.Registrar.Name);
        Assert.Equal("9999", response.Registrar.IanaId);
        Assert.Equal("https://radix.website/", response.Registrar.Url);
        Assert.Equal("whois.radix.host", response.Registrar.WhoisServer.Value);

        Assert.Equal(new DateTime(2026, 05, 26, 00, 02, 58, 101, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2014, 04, 10, 09, 14, 07, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 04, 10, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

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
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns03.trs-dns.com", response.NameServers[0]);
        Assert.Equal("ns03.trs-dns.net", response.NameServers[1]);

        // Domain Status
        Assert.Equal(4, response.DomainStatus.Count);
        Assert.Equal("serverTransferProhibited", response.DomainStatus[0]);

        Assert.Equal("signedDelegation", response.DnsSecStatus);
        Assert.Equal(19, response.FieldsParsed);
    }
}
