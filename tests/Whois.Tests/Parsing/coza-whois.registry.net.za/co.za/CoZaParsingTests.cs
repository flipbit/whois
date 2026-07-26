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

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("coza-whois.registry.net.za", "co.za", "found", "fnb.co.za.txt");
        var response = parser.Parse("coza-whois.registry.net.za", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal("fnb.co.za", response.DomainName.ToString());
        Assert.Equal("1zw3s_DOMAIN-CO.ZA", response.RegistryDomainId);

        Assert.Equal("Lexsynergy Limited", response.Registrar.Name);
        Assert.Equal("whois.lexsynergy.com", response.Registrar.WhoisServer.Value);

        Assert.Equal(new DateTime(2025, 12, 1, 23, 41, 53, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1994, 12, 31, 22, 0, 0, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2026, 12, 31, 22, 0, 0, DateTimeKind.Utc), response.Expiration);
        Assert.Null(response.Registrant.Name);
        Assert.Equal("FirstRand Bank Limited", response.Registrant.Organization);

        Assert.Equal(1, response.Registrant.Address.Count);
        Assert.Equal("ZA", response.Registrant.Address[0]);

        Assert.Null(response.Registrant.TelephoneNumber);
        Assert.Null(response.Registrant.Email);

        Assert.Null(response.AdminContact);



        Assert.Null(response.BillingContact);



        Assert.Null(response.TechnicalContact);




        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns01.fnbconnect.co.za", response.NameServers[0]);
        Assert.Equal("ns02.fnbconnect.co.za", response.NameServers[1]);
        Assert.Equal("ns03.fnbconnect.co.za", response.NameServers[2]);
        Assert.Equal("ns04.fnbconnect.co.za", response.NameServers[3]);

        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);
    }

    [Fact]
    public void Test_throttled()
    {
        var sample = SampleReader.Read("coza-whois.registry.net.za", "co.za", "throttled", "throttled.txt");
        var response = parser.Parse("coza-whois.registry.net.za", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Throttled, response.Status);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("coza-whois.registry.net.za", "co.za", "not-found", "nosuchdomainregistered.co.za.txt");
        var response = parser.Parse("coza-whois.registry.net.za", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal("nosuchdomainregistered.co.za", response.DomainName.ToString());
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("coza-whois.registry.net.za", "co.za", "found", "google.co.za.txt");
        var response = parser.Parse("coza-whois.registry.net.za", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal("google.co.za", response.DomainName.ToString());
        Assert.Equal("1szmf_DOMAIN-CO.ZA", response.RegistryDomainId);

        Assert.Equal("MarkMonitor", response.Registrar.Name);
        Assert.Equal("whois.markmonitor.com", response.Registrar.WhoisServer.Value);

        Assert.Equal(new DateTime(2026, 5, 24, 10, 24, 57, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2001, 6, 25, 20, 37, 59, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 6, 25, 20, 37, 59, DateTimeKind.Utc), response.Expiration);
        Assert.Null(response.Registrant.Name);

        Assert.Equal(1, response.Registrant.Address.Count);
        Assert.Equal("US", response.Registrant.Address[0]);

        Assert.Null(response.Registrant.TelephoneNumber);
        Assert.Null(response.Registrant.FaxNumber);
        Assert.Null(response.Registrant.Email);

        Assert.Null(response.AdminContact);



        Assert.Null(response.BillingContact);



        Assert.Null(response.TechnicalContact);




        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        Assert.Equal(3, response.DomainStatus.Count);
        Assert.Equal("serverDeleteProhibited", response.DomainStatus[0]);
    }
}
