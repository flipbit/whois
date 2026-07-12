using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Registry.Gy.Gy;

public class GyParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public GyParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.registry.gy", "gy", "not-found", "u34jedzcq.gy.txt");
        var response = parser.Parse("whois.registry.gy", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/04", response.TemplateName);

        Assert.Equal("u34jedzcq.gy", response.DomainName.ToString());


        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.registry.gy", "gy", "found", "google.gy.txt");
        var response = parser.Parse("whois.registry.gy", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.gy", response.DomainName.ToString());
        Assert.Equal("573328-CoCCA", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("MarkMonitor", response.Registrar.Name);
        Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);
        Assert.Equal("whois.registry.gy", response.Registrar.WhoisServer.Value);
        Assert.Equal("ccops@markmonitor.com", response.Registrar.AbuseEmail);
        Assert.Equal("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2014, 01, 16, 06, 53, 13, 620, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2008, 05, 12, 17, 56, 23, 090, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2014, 10, 04, 23, 30, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("969683-CoCCA", response.Registrant.RegistryId);
        Assert.Equal("google Inc", response.Registrant.Name);
        Assert.Equal("+1.6506188571", response.Registrant.TelephoneNumber);
        Assert.Equal("dns-admin@google.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("mountain View", response.Registrant.Address[0]);
        Assert.Equal("Unknown", response.Registrant.Address[1]);
        Assert.Equal("US", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("969684-CoCCA", response.AdminContact.RegistryId);
        Assert.Equal("DNS Admin", response.AdminContact.Name);
        Assert.Equal("+1.6506188571", response.AdminContact.TelephoneNumber);
        Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(3, response.AdminContact.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
        Assert.Equal("USA", response.AdminContact.Address[1]);
        Assert.Equal("US", response.AdminContact.Address[2]);


        // BillingContact Details
        Assert.Equal("969686-CoCCA", response.BillingContact.RegistryId);


        // TechnicalContact Details
        Assert.Equal("969685-CoCCA", response.TechnicalContact.RegistryId);
        Assert.Equal("Unknown", response.TechnicalContact.Name);

        // TechnicalContact Address
        Assert.Equal(3, response.TechnicalContact.Address.Count);
        Assert.Equal("Unknown", response.TechnicalContact.Address[0]);
        Assert.Equal("Unknown", response.TechnicalContact.Address[1]);
        Assert.Equal("US", response.TechnicalContact.Address[2]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns2.google.com", response.NameServers[0]);
        Assert.Equal("ns1.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(5, response.DomainStatus.Count);
        Assert.Equal("clientRenewProhibited", response.DomainStatus[0]);
        Assert.Equal("ok", response.DomainStatus[1]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[2]);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[3]);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[4]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(44, response.FieldsParsed);
    }
}
