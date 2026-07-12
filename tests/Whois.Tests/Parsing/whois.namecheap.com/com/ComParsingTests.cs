using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Namecheap.Com.Com;

public class ComParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public ComParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.namecheap.com", "com", "found", "slavichy.com.txt");
        var response = parser.Parse("whois.namecheap.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("slavichy.com", response.DomainName.ToString());
        Assert.Equal("2175421662_DOMAIN_COM-VRSN", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("NAMECHEAP INC", response.Registrar.Name);
        Assert.Equal("1068", response.Registrar.IanaId);
        Assert.Equal("http://www.namecheap.com", response.Registrar.Url);
        Assert.Equal("abuse@namecheap.com", response.Registrar.AbuseEmail);
        Assert.Equal("+1.6613102107", response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2019, 09, 17, 10, 07, 38, 810, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2017, 10, 17, 17, 37, 03, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2020, 10, 17, 17, 37, 03, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("WhoisGuard Protected", response.Registrant.Name);
        Assert.Equal("+507.8365503", response.Registrant.TelephoneNumber);
        Assert.Equal("+51.17057182", response.Registrant.FaxNumber);
        Assert.Equal("2d053ce12e12426e89791ea5f9616208.protect@whoisguard.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("P.O. Box 0823-03411", response.Registrant.Address[0]);
        Assert.Equal("Panama", response.Registrant.Address[1]);
        Assert.Equal("Panama", response.Registrant.Address[2]);
        Assert.Equal("PA", response.Registrant.Address[3]);


        // AdminContact Details
        Assert.Equal("WhoisGuard Protected", response.AdminContact.Name);
        Assert.Equal("+507.8365503", response.AdminContact.TelephoneNumber);
        Assert.Equal("+51.17057182", response.AdminContact.FaxNumber);
        Assert.Equal("2d053ce12e12426e89791ea5f9616208.protect@whoisguard.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("P.O. Box 0823-03411", response.AdminContact.Address[0]);
        Assert.Equal("Panama", response.AdminContact.Address[1]);
        Assert.Equal("Panama", response.AdminContact.Address[2]);
        Assert.Equal("PA", response.AdminContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("WhoisGuard Protected", response.TechnicalContact.Name);
        Assert.Equal("+507.8365503", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+51.17057182", response.TechnicalContact.FaxNumber);
        Assert.Equal("2d053ce12e12426e89791ea5f9616208.protect@whoisguard.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(4, response.TechnicalContact.Address.Count);
        Assert.Equal("P.O. Box 0823-03411", response.TechnicalContact.Address[0]);
        Assert.Equal("Panama", response.TechnicalContact.Address[1]);
        Assert.Equal("Panama", response.TechnicalContact.Address[2]);
        Assert.Equal("PA", response.TechnicalContact.Address[3]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("heather.ns.cloudflare.com", response.NameServers[0]);
        Assert.Equal("josh.ns.cloudflare.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(46, response.FieldsParsed);
    }
}
