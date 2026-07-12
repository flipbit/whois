using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Mg.Mg;

public class MgParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public MgParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.mg", "mg", "not-found", "u34jedzcq.mg.txt");
        var response = parser.Parse("whois.nic.mg", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/05", response.TemplateName);

        Assert.Equal("u34jedzcq.mg", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.mg", "mg", "found", "google.mg.txt");
        var response = parser.Parse("whois.nic.mg", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.mg", response.DomainName.ToString());
        Assert.Equal("1915-nicmg", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("MarkMonitor", response.Registrar.Name);
        Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);
        Assert.Equal("ccops@markmonitor.com", response.Registrar.AbuseEmail);
        Assert.Equal("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2013, 10, 29, 15, 13, 49, 869, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2009, 06, 18, 08, 38, 20, 671, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2014, 11, 26, 21, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("4112-nicmg", response.Registrant.RegistryId);
        Assert.Equal("GOOGLE INC", response.Registrant.Name);
        Assert.Equal("GOOGLE INC", response.Registrant.Organization);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("Street Migrate", response.Registrant.Address[0]);
        Assert.Equal("Antananarivo", response.Registrant.Address[1]);
        Assert.Equal("Antananarivo", response.Registrant.Address[2]);
        Assert.Equal("101", response.Registrant.Address[3]);
        Assert.Equal("MG", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("ccops@markmonitor.com", response.AdminContact.Email);


        // TechnicalContact Details
        Assert.Equal("4113-nicmg", response.TechnicalContact.RegistryId);
        Assert.Equal("Rafaralahisoa Emmanuel", response.TechnicalContact.Name);
        Assert.Equal("DTS", response.TechnicalContact.Organization);
        Assert.Equal("+261.202220359", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+261.202220360", response.TechnicalContact.FaxNumber);

        // TechnicalContact Address
        Assert.Equal(4, response.TechnicalContact.Address.Count);
        Assert.Equal("Immeuble Galaxy", response.TechnicalContact.Address[0]);
        Assert.Equal("Antananarivo", response.TechnicalContact.Address[1]);
        Assert.Equal("101", response.TechnicalContact.Address[2]);
        Assert.Equal("MG", response.TechnicalContact.Address[3]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(5, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);
        Assert.Equal("clientRenewProhibited", response.DomainStatus[1]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[2]);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[3]);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[4]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(38, response.FieldsParsed);
    }
}
