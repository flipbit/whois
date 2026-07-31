using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Design.Design;

public class DesignParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public DesignParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.design", "design", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.design", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.design", "design", "found", "toplevel.design.txt");
        var response = parser.Parse("whois.nic.design", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("toplevel.design", response.DomainName.ToString());
        Assert.Equal("REDACTED FOR PRIVACY", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("Porkbun", response.Registrar.Name);
        Assert.Equal("1861", response.Registrar.IanaId);
        Assert.Null(response.Registrar.WhoisServer);

        Assert.Equal(new DateTime(2026, 02, 20, 01, 46, 05, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2017, 02, 16, 20, 11, 45, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 02, 16, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.RegistryId);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Name);
        Assert.Equal("Top Level Design LLC", response.Registrant.Organization);
        Assert.Null(response.Registrant.TelephoneNumber);
        Assert.Null(response.Registrant.FaxNumber);
        Assert.Null(response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Address[0]);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Address[1]);
        Assert.Equal("Oregon", response.Registrant.Address[2]);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Address[3]);
        Assert.Equal("US", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // BillingContact Details
        Assert.Null(response.BillingContact);

        // BillingContact Address


        // TechnicalContact Details
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.RegistryId);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Name);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Organization);
        Assert.Null(response.TechnicalContact.TelephoneNumber);
        Assert.Null(response.TechnicalContact.FaxNumber);
        Assert.Null(response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[0]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[1]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[2]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[3]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("curitiba.ns.porkbun.com", response.NameServers[0]);
        Assert.Equal("salvador.ns.porkbun.com", response.NameServers[1]);
        Assert.Equal("fortaleza.ns.porkbun.com", response.NameServers[2]);
        Assert.Equal("maceio.ns.porkbun.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(2, response.DomainStatus.Count);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(34, response.FieldsParsed);
    }
}
