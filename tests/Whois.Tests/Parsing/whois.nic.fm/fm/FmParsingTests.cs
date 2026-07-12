using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Fm.Fm;

public class FmParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public FmParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.fm", "fm", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.fm", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.fm", "fm", "found", "google.fm.txt");
        var response = parser.Parse("whois.nic.fm", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/02", response.TemplateName);

        Assert.Equal("google.fm", response.DomainName.ToString());
        Assert.Equal("D34865469-CNIC", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);
        Assert.Equal("292", response.Registrar.IanaId);
        Assert.Equal("whois.markmonitor.com", response.Registrar.WhoisServer.Value);
        Assert.Equal("ccops@markmonitor.com", response.Registrar.AbuseEmail);
        Assert.Equal("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2025, 12, 02, 19, 21, 42, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2000, 09, 05, 23, 59, 59, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2026, 09, 04, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

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
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns3.google.com", response.NameServers[1]);
        Assert.Equal("ns2.google.com", response.NameServers[2]);

        // Domain Status
        Assert.Equal(3, response.DomainStatus.Count);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[1]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(18, response.FieldsParsed);
    }
}
