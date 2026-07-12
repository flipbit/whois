using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Comlaude.Com.Com;

public class ComParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public ComParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found_adobe_com()
    {
        var sample = SampleReader.Read("whois.comlaude.com", "com", "found", "adobe.com.txt");

        var response = parser.Parse("whois.comlaude.com", sample);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("adobe.com", response.DomainName.ToString());
        Assert.Equal("4364022_DOMAIN_COM-VRSN", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("NOM-IQ Ltd dba Com Laude", response.Registrar.Name);
        Assert.Equal("470", response.Registrar.IanaId);
        Assert.Equal("http://www.comlaude.com", response.Registrar.Url);
        Assert.Equal("whois.comlaude.com", response.Registrar.WhoisServer.Value);
        Assert.Equal("abuse@comlaude.com", response.Registrar.AbuseEmail);
        Assert.Equal("+44.2074218250", response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2018, 10, 18, 17, 09, 58, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1986, 11, 17, 05, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2019, 05, 17, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Domain Administrator", response.Registrant.Name);
        Assert.Equal("Adobe Inc.", response.Registrant.Organization);
        Assert.Equal("+1.4085366000", response.Registrant.TelephoneNumber);
        Assert.Equal("dns-admin@adobe.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("345 Park Avenue", response.Registrant.Address[0]);
        Assert.Equal("San Jose", response.Registrant.Address[1]);
        Assert.Equal("California", response.Registrant.Address[2]);
        Assert.Equal("95110", response.Registrant.Address[3]);
        Assert.Equal("US", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("Domain Administrator", response.AdminContact.Name);
        Assert.Equal("Adobe Inc.", response.AdminContact.Organization);
        Assert.Equal("+1.4085366000", response.AdminContact.TelephoneNumber);
        Assert.Equal("dns-admin@adobe.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("345 Park Avenue", response.AdminContact.Address[0]);
        Assert.Equal("San Jose", response.AdminContact.Address[1]);
        Assert.Equal("California", response.AdminContact.Address[2]);
        Assert.Equal("95110", response.AdminContact.Address[3]);
        Assert.Equal("US", response.AdminContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.RegistryId);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Name);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Organization);
        Assert.Equal("adobe.com-Tech@anonymised.email", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[0]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[1]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[2]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[3]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(7, response.NameServers.Count);
        Assert.Equal("a1-217.akam.net", response.NameServers[0]);
        Assert.Equal("a10-64.akam.net", response.NameServers[1]);
        Assert.Equal("a13-65.akam.net", response.NameServers[2]);
        Assert.Equal("a26-66.akam.net", response.NameServers[3]);
        Assert.Equal("a28-67.akam.net", response.NameServers[4]);
        Assert.Equal("a7-64.akam.net", response.NameServers[5]);
        Assert.Equal("adobe-dns-01.adobe.com", response.NameServers[6]);

        // Domain Status
        Assert.Equal(4, response.DomainStatus.Count);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[0]);
        Assert.Equal("serverDeleteProhibited", response.DomainStatus[1]);
        Assert.Equal("serverTransferProhibited", response.DomainStatus[2]);
        Assert.Equal("serverUpdateProhibited", response.DomainStatus[3]);

        Assert.Equal("Unsigned Delegation", response.DnsSecStatus);
        Assert.Equal(53, response.FieldsParsed);
    }
}
