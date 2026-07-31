using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Sx.Sx;

public class SxParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public SxParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_other_status_premium_name()
    {
        var sample = SampleReader.Read("whois.sx", "sx", "found", "domain.sx.txt");
        var response = parser.Parse("whois.sx", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("domain.sx", response.DomainName.ToString());

        Assert.Equal(47, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.sx", "sx", "not-found", "not_found.txt");
        var response = parser.Parse("whois.sx", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.sx/sx/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.sx", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.sx", "sx", "found", "found.txt");
        var response = parser.Parse("whois.sx", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("whois.sx", response.DomainName.ToString());
        Assert.Equal("d5-sx", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("SX Registry O", response.Registrar.Name);

        Assert.Equal(new DateTime(2013, 02, 25, 16, 50, 39, 204, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2011, 12, 09, 14, 07, 22, 794, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2022, 12, 09, 14, 07, 22, 794, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("C65", response.Registrant.RegistryId);
        Assert.Equal("SX Registry SA administrator", response.Registrant.Name);
        Assert.Equal("SX Registry SA", response.Registrant.Organization);
        Assert.Equal("registry@registry.sx", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("2, rue Léon Laval", response.Registrant.Address[0]);
        Assert.Equal("Leudelange", response.Registrant.Address[1]);
        Assert.Equal("L3372", response.Registrant.Address[2]);
        Assert.Equal("LUXEMBOURG", response.Registrant.Address[3]);


        // AdminContact Details
        Assert.Equal("C65", response.AdminContact.RegistryId);
        Assert.Equal("SX Registry SA administrator", response.AdminContact.Name);
        Assert.Equal("SX Registry SA", response.AdminContact.Organization);
        Assert.Equal("registry@registry.sx", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("2, rue Léon Laval", response.AdminContact.Address[0]);
        Assert.Equal("Leudelange", response.AdminContact.Address[1]);
        Assert.Equal("L3372", response.AdminContact.Address[2]);
        Assert.Equal("LUXEMBOURG", response.AdminContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("C65", response.TechnicalContact.RegistryId);
        Assert.Equal("SX Registry SA administrator", response.TechnicalContact.Name);
        Assert.Equal("SX Registry SA", response.TechnicalContact.Organization);
        Assert.Equal("registry@registry.sx", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(4, response.TechnicalContact.Address.Count);
        Assert.Equal("2, rue Léon Laval", response.TechnicalContact.Address[0]);
        Assert.Equal("Leudelange", response.TechnicalContact.Address[1]);
        Assert.Equal("L3372", response.TechnicalContact.Address[2]);
        Assert.Equal("LUXEMBOURG", response.TechnicalContact.Address[3]);


        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("a.ns.sx", response.NameServers[0]);
        Assert.Equal("b.ns.sx", response.NameServers[1]);
        Assert.Equal("c.ns.sx", response.NameServers[2]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal("signedDelegation", response.DnsSecStatus);
        Assert.Equal(36, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_unavailable()
    {
        var sample = SampleReader.Read("whois.sx", "sx", "unavailable", "domain-unavailable.sx.txt");
        var response = parser.Parse("whois.sx", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Unavailable, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.sx/sx/unavailable/01", response.TemplateName);

        Assert.Equal("domain-unavailable.sx", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }
}
