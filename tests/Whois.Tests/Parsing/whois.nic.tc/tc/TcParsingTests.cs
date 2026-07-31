using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Tc.Tc;

public class TcParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public TcParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.tc", "tc", "not-found", "u34jedzcq.tc.txt");
        var response = parser.Parse("whois.nic.tc", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/04", response.TemplateName);

        Assert.Equal("u34jedzcq.tc", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.tc", "tc", "found", "google.tc.txt");
        var response = parser.Parse("whois.nic.tc", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.tc", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Isimtescil Bilisim A.S.", response.Registrar.Name);
        Assert.Null(response.Registrar.IanaId);
        Assert.Equal("whois.nic.tc", response.Registrar.WhoisServer.Value);
        Assert.Null(response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2014, 12, 24, 05, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2026, 12, 24, 05, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

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
        Assert.Equal("ns1.google.tc", response.NameServers[0]);
        Assert.Equal("ns2.google.tc", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(12, response.FieldsParsed);
    }
}
