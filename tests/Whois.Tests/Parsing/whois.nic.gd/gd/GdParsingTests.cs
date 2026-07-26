using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Gd.Gd;

public class GdParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public GdParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.gd", "gd", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.gd", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.gd/gd/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.gd", "gd", "found", "google.gd.txt");
        var response = parser.Parse("whois.nic.gd", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/02", response.TemplateName);

        Assert.Equal("google.gd", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);
        Assert.Null(response.Registrar.Url);

        Assert.Equal(new DateTime(2025, 12, 02, 19, 22, 07, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2006, 12, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2026, 12, 11, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

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
        Assert.Equal("ns2.google.com", response.NameServers[0]);
        Assert.Equal("ns1.google.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(3, response.DomainStatus.Count);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[1]);

        Assert.Equal(17, response.FieldsParsed);
    }

    [Fact]
    public void Test_reserved()
    {
        var sample = SampleReader.Read("whois.nic.gd", "gd", "reserved", "reserved.txt");
        var response = parser.Parse("whois.nic.gd", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Reserved, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.gd/gd/reserved/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }
}
