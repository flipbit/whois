using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Hn.Hn;

public class HnParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public HnParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.hn", "hn", "not-found", "u34jedzcq.hn.txt");
        var response = parser.Parse("whois.nic.hn", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/04", response.TemplateName);

        Assert.Equal("u34jedzcq.hn", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.hn", "hn", "found", "google.hn.txt");
        var response = parser.Parse("whois.nic.hn", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.hn", response.DomainName.ToString());
        Assert.Equal("801220-CoCCA", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("MarkMonitor", response.Registrar.Name);
        Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);
        Assert.Null(response.Registrar.WhoisServer);
        Assert.Null(response.Registrar.AbuseEmail);
        Assert.Null(response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2026, 02, 03, 10, 42, 11, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2003, 03, 07, 05, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 03, 07, 05, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("1671988-CoCCA", response.Registrant.RegistryId);
        Assert.Equal("Domain Administrator", response.Registrant.Name);
        Assert.Null(response.Registrant.Organization);
        Assert.Equal("+1.6502530000", response.Registrant.TelephoneNumber);
        Assert.Null(response.Registrant.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
        Assert.Equal("Mountain View", response.Registrant.Address[1]);
        Assert.Equal("CA", response.Registrant.Address[2]);
        Assert.Equal("94043", response.Registrant.Address[3]);
        Assert.Equal("US", response.Registrant.Address[4]);


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
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(4, response.DomainStatus.Count);
        Assert.Equal("active", response.DomainStatus[0]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[1]);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[2]);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[3]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(25, response.FieldsParsed);
    }
}
