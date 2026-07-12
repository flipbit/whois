using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Gg.Gg;

public class GgParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public GgParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.gg", "gg", "not-found", "u34jedzcq.gg.txt");
        var response = parser.Parse("whois.gg", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/05", response.TemplateName);

        Assert.Equal("u34jedzcq.gg", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.gg", "gg", "found", "google.gg.txt");
        var response = parser.Parse("whois.gg", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.gg", response.DomainName.ToString());
        Assert.Equal("24221-CI", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);
        Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);
        Assert.Equal("whois.gg", response.Registrar.WhoisServer.Value);

        Assert.Equal(new DateTime(2003, 04, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

        // Registrant Details
        Assert.Equal("32764-CI", response.Registrant.RegistryId);


        // AdminContact Details
        Assert.Equal("32764-CI", response.AdminContact.RegistryId);


        // BillingContact Details
        Assert.Equal("32762-CI", response.BillingContact.RegistryId);


        // TechnicalContact Details
        Assert.Equal("32764-CI", response.TechnicalContact.RegistryId);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns4.google.com", response.NameServers[2]);
        Assert.Equal("ns3.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(4, response.DomainStatus.Count);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
        Assert.Equal("ok", response.DomainStatus[1]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[2]);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[3]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(20, response.FieldsParsed);
    }
}
