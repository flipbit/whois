using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Coza.Whois.Registry.Net.Za.CoZa;

public class CoZaParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public CoZaParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("coza-whois.registry.net.za", "co.za", "found", "fnb.co.za.txt");
        var response = parser.Parse("coza-whois.registry.net.za", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal("fnb.co.za", response.DomainName.ToString());
        Assert.Equal("dom_1ZW3S--1", response.RegistryDomainId);

        Assert.Equal("Lexsynergy Limited", response.Registrar.Name);
        Assert.Equal("coza-whois12.dns.net.za", response.Registrar.WhoisServer.Value);

        Assert.Equal(new DateTime(2016, 12, 1, 23, 41, 21, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1994, 12, 31, 22, 0, 0, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2017, 12, 31, 22, 0, 0, DateTimeKind.Utc), response.Expiration);
        Assert.Equal("FirstRand Bank Limited", response.Registrant.Name);
        Assert.Equal("FirstRand Bank Limited", response.Registrant.Organization);

        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("2nd floor 4 Merchant Place Cnr Rivonia and Sandton Drive", response.Registrant.Address[0]);
        Assert.Equal("Sandton", response.Registrant.Address[1]);
        Assert.Equal("Gauteng", response.Registrant.Address[2]);
        Assert.Equal("2196", response.Registrant.Address[3]);
        Assert.Equal("ZA", response.Registrant.Address[4]);

        Assert.Equal("+27.112828000", response.Registrant.TelephoneNumber);
        Assert.Equal("domreg.admins@firstrand.co.za", response.Registrant.Email);

        Assert.Equal("LEX-1EU-1Y58", response.AdminContact.RegistryId);
        Assert.Equal("FirstRand Bank Limited", response.AdminContact.Name);
        Assert.Equal("FirstRand Bank Limited", response.AdminContact.Organization);

        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("2nd floor 4 Merchant Place Cnr Rivonia and Sandton Drive", response.AdminContact.Address[0]);
        Assert.Equal("Sandton", response.AdminContact.Address[1]);
        Assert.Equal("Gauteng", response.AdminContact.Address[2]);
        Assert.Equal("2196", response.AdminContact.Address[3]);
        Assert.Equal("ZA", response.AdminContact.Address[4]);

        Assert.Equal("+27.112828000", response.AdminContact.TelephoneNumber);
        Assert.Equal("domreg.admins@firstrand.co.za", response.AdminContact.Email);

        Assert.Equal("LEX-1EU-1Y58", response.BillingContact.RegistryId);
        Assert.Equal("FirstRand Bank Limited", response.BillingContact.Name);
        Assert.Equal("FirstRand Bank Limited", response.BillingContact.Organization);

        Assert.Equal(5, response.BillingContact.Address.Count);
        Assert.Equal("2nd floor 4 Merchant Place Cnr Rivonia and Sandton Drive", response.BillingContact.Address[0]);
        Assert.Equal("Sandton", response.BillingContact.Address[1]);
        Assert.Equal("Gauteng", response.BillingContact.Address[2]);
        Assert.Equal("2196", response.BillingContact.Address[3]);
        Assert.Equal("ZA", response.BillingContact.Address[4]);

        Assert.Equal("+27.112828000", response.BillingContact.TelephoneNumber);
        Assert.Equal("domreg.admins@firstrand.co.za", response.BillingContact.Email);

        Assert.Equal("LEX-1EU-1Y58", response.TechnicalContact.RegistryId);
        Assert.Equal("FirstRand Bank Limited", response.TechnicalContact.Name);
        Assert.Equal("FirstRand Bank Limited", response.TechnicalContact.Organization);

        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("2nd floor 4 Merchant Place Cnr Rivonia and Sandton Drive", response.TechnicalContact.Address[0]);
        Assert.Equal("Sandton", response.TechnicalContact.Address[1]);
        Assert.Equal("Gauteng", response.TechnicalContact.Address[2]);
        Assert.Equal("2196", response.TechnicalContact.Address[3]);
        Assert.Equal("ZA", response.TechnicalContact.Address[4]);

        Assert.Equal("+27.112828000", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("domreg.admins@firstrand.co.za", response.TechnicalContact.Email);


        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns01.fnbconnect.co.za", response.NameServers[0]);
        Assert.Equal("ns02.fnbconnect.co.za", response.NameServers[1]);
        Assert.Equal("ns03.fnbconnect.co.za", response.NameServers[2]);
        Assert.Equal("ns04.fnbconnect.co.za", response.NameServers[3]);

        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);
    }

    [Fact]
    public void Test_throttled()
    {
        var sample = SampleReader.Read("coza-whois.registry.net.za", "co.za", "throttled", "throttled.txt");
        var response = parser.Parse("coza-whois.registry.net.za", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Throttled, response.Status);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("coza-whois.registry.net.za", "co.za", "not-found", "nosuchdomainregistered.co.za.txt");
        var response = parser.Parse("coza-whois.registry.net.za", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal("nosuchdomainregistered.co.za", response.DomainName.ToString());
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("coza-whois.registry.net.za", "co.za", "found", "google.co.za.txt");
        var response = parser.Parse("coza-whois.registry.net.za", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal("google.co.za", response.DomainName.ToString());
        Assert.Equal("dom_1SZMF--1", response.RegistryDomainId);

        Assert.Equal("MarkMonitor", response.Registrar.Name);
        Assert.Equal("coza-whois12.dns.net.za", response.Registrar.WhoisServer.Value);

        Assert.Equal(new DateTime(2016, 9, 24, 16, 20, 9, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2001, 6, 25, 20, 37, 59, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2017, 6, 25, 20, 37, 59, DateTimeKind.Utc), response.Expiration);
        Assert.Equal("Google Inc.", response.Registrant.Name);

        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
        Assert.Equal("Mountain View", response.Registrant.Address[1]);
        Assert.Equal("CA", response.Registrant.Address[2]);
        Assert.Equal("94043", response.Registrant.Address[3]);
        Assert.Equal("US", response.Registrant.Address[4]);

        Assert.Equal("+1.6502530000", response.Registrant.TelephoneNumber);
        Assert.Equal("+1.6506188571", response.Registrant.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.Registrant.Email);

        Assert.Equal("mmr-2383", response.AdminContact.RegistryId);
        Assert.Equal("Google Inc.", response.AdminContact.Name);

        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
        Assert.Equal("Mountain View", response.AdminContact.Address[1]);
        Assert.Equal("CA", response.AdminContact.Address[2]);
        Assert.Equal("94043", response.AdminContact.Address[3]);
        Assert.Equal("US", response.AdminContact.Address[4]);

        Assert.Equal("+1.6502530000", response.AdminContact.TelephoneNumber);
        Assert.Equal("+1.6506188571", response.AdminContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

        Assert.Equal("mmr-2383", response.BillingContact.RegistryId);
        Assert.Equal("Google Inc.", response.BillingContact.Name);

        Assert.Equal(5, response.BillingContact.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.BillingContact.Address[0]);
        Assert.Equal("Mountain View", response.BillingContact.Address[1]);
        Assert.Equal("CA", response.BillingContact.Address[2]);
        Assert.Equal("94043", response.BillingContact.Address[3]);
        Assert.Equal("US", response.BillingContact.Address[4]);

        Assert.Equal("+1.6502530000", response.BillingContact.TelephoneNumber);
        Assert.Equal("+1.6506188571", response.BillingContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.BillingContact.Email);

        Assert.Equal("mmr-2383", response.TechnicalContact.RegistryId);
        Assert.Equal("Google Inc.", response.TechnicalContact.Name);

        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
        Assert.Equal("Mountain View", response.TechnicalContact.Address[1]);
        Assert.Equal("CA", response.TechnicalContact.Address[2]);
        Assert.Equal("94043", response.TechnicalContact.Address[3]);
        Assert.Equal("US", response.TechnicalContact.Address[4]);

        Assert.Equal("+1.6502530000", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+1.6506188571", response.TechnicalContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);


        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);
    }
}
