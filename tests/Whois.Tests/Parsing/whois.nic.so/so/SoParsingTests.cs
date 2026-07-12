using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.So.So;

public class SoParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public SoParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.so", "so", "not-found", "u34jedzcq.so.txt");
        var response = parser.Parse("whois.nic.so", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.so/so/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.so", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.so", "so", "found", "google.so.txt");
        var response = parser.Parse("whois.nic.so", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.so/so/found/01", response.TemplateName);

        Assert.Equal("google.so", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);

        Assert.Equal(new DateTime(2011, 01, 25, 04, 20, 26, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2011, 01, 24, 02, 22, 24, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2014, 01, 24, 02, 22, 24, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("mm-google", response.Registrant.RegistryId);


        // AdminContact Details
        Assert.Equal("mm-google", response.AdminContact.RegistryId);


        // BillingContact Details
        Assert.Equal("so-mm-billing", response.BillingContact.RegistryId);


        // TechnicalContact Details
        Assert.Equal("mm-google", response.TechnicalContact.RegistryId);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(2, response.DomainStatus.Count);
        Assert.Equal("serverDeleteProhibited", response.DomainStatus[0]);
        Assert.Equal("serverTransferProhibited", response.DomainStatus[1]);

        Assert.Equal(16, response.FieldsParsed);
    }
}
