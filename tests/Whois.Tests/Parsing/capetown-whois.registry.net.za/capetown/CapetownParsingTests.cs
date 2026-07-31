using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Capetown.Whois.Registry.Net.Za.Capetown;

public class CapetownParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public CapetownParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("capetown-whois.registry.net.za", "capetown", "not-found", "nosuchdomain.capetown.txt");
        var response = parser.Parse("capetown-whois.registry.net.za", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);
        Assert.Equal("nosuchdomain.capetown", response.DomainName.ToString());

    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("capetown-whois.registry.net.za", "capetown", "found", "registry.capetown.txt");
        var response = parser.Parse("capetown-whois.registry.net.za", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal("registry.capetown", response.DomainName.ToString());
        Assert.Equal("dom_3K3-9999", response.RegistryDomainId);

        Assert.Equal("capetown-whois2.registry.net.za", response.Registrar.WhoisServer.Value);

        Assert.Equal(new DateTime(2015, 5, 30, 9, 21, 0, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2015, 4, 1, 7, 41, 59, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2016, 4, 1, 7, 41, 59, DateTimeKind.Utc), response.Expiration);
        Assert.Equal("LEX-7IC-235J", response.Registrant.RegistryId);
        Assert.Equal("Lucky Mokgabudi Masilela", response.Registrant.Name);
        Assert.Equal("ZA Central Registry", response.Registrant.Organization);

        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("COZA House, Gazelle Close Corporate Park South", response.Registrant.Address[0]);
        Assert.Equal("Midrand", response.Registrant.Address[1]);
        Assert.Equal("Gauteng", response.Registrant.Address[2]);
        Assert.Equal("1685", response.Registrant.Address[3]);
        Assert.Equal("ZA", response.Registrant.Address[4]);

        Assert.Equal("+27.113140077", response.Registrant.TelephoneNumber);
        Assert.Equal("+27.113140088", response.Registrant.FaxNumber);
        Assert.Equal("legal@co.za", response.Registrant.Email);

        Assert.Equal("LEX-7IC-235J", response.AdminContact.RegistryId);
        Assert.Equal("Lucky Mokgabudi Masilela", response.AdminContact.Name);
        Assert.Equal("ZA Central Registry", response.AdminContact.Organization);

        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("COZA House, Gazelle Close Corporate Park South", response.AdminContact.Address[0]);
        Assert.Equal("Midrand", response.AdminContact.Address[1]);
        Assert.Equal("Gauteng", response.AdminContact.Address[2]);
        Assert.Equal("1685", response.AdminContact.Address[3]);
        Assert.Equal("ZA", response.AdminContact.Address[4]);

        Assert.Equal("+27.113140077", response.AdminContact.TelephoneNumber);
        Assert.Equal("+27.113140088", response.AdminContact.FaxNumber);
        Assert.Equal("legal@co.za", response.AdminContact.Email);

        Assert.Equal("LEX-1-1XMT", response.BillingContact.RegistryId);
        Assert.Equal("Domain Name Department", response.BillingContact.Name);
        Assert.Equal("Lexsynergy Limited", response.BillingContact.Organization);

        Assert.Equal(4, response.BillingContact.Address.Count);
        Assert.Equal("130 Hampstead House 176 Finchley Road", response.BillingContact.Address[0]);
        Assert.Equal("London", response.BillingContact.Address[1]);
        Assert.Equal("NW3 6BT", response.BillingContact.Address[2]);
        Assert.Equal("GB", response.BillingContact.Address[3]);

        Assert.Equal("+44.2081331319", response.BillingContact.TelephoneNumber);
        Assert.Equal("+44.2081331319", response.BillingContact.FaxNumber);
        Assert.Equal("domains@lexsynergy.com", response.BillingContact.Email);

        Assert.Equal("LEX-7IC-235J", response.TechnicalContact.RegistryId);
        Assert.Equal("Lucky Mokgabudi Masilela", response.TechnicalContact.Name);
        Assert.Equal("ZA Central Registry", response.TechnicalContact.Organization);

        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("COZA House, Gazelle Close Corporate Park South", response.TechnicalContact.Address[0]);
        Assert.Equal("Midrand", response.TechnicalContact.Address[1]);
        Assert.Equal("Gauteng", response.TechnicalContact.Address[2]);
        Assert.Equal("1685", response.TechnicalContact.Address[3]);
        Assert.Equal("ZA", response.TechnicalContact.Address[4]);

        Assert.Equal("+27.113140077", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+27.113140088", response.TechnicalContact.FaxNumber);
        Assert.Equal("legal@co.za", response.TechnicalContact.Email);


        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.nic.capetown", response.NameServers[0]);
        Assert.Equal("ns1.dnservices.co.za", response.NameServers[1]);
    }
}
