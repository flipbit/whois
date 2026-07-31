using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Joburg.Whois.Registry.Net.Za.Joburg;

public class JoburgParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public JoburgParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("joburg-whois.registry.net.za", "joburg", "not-found", "nosuchdomain.joburg.txt");
        var response = parser.Parse("joburg-whois.registry.net.za", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(2, response.FieldsParsed);
        Assert.Equal(0, response.ParsingErrors);

        Assert.Equal("nosuchdomain.joburg", response.DomainName.ToString());
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("joburg-whois.registry.net.za", "joburg", "found", "usedautos.joburg.txt");
        var response = parser.Parse("joburg-whois.registry.net.za", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(55, response.FieldsParsed);
        Assert.Equal(0, response.ParsingErrors);

        Assert.Equal("usedautos.joburg", response.DomainName.ToString());
        Assert.Equal("dom_7P-9999", response.RegistryDomainId);

        Assert.Equal("Lexsynergy", response.Registrar.Name);
        Assert.Equal("joburg-whois2.registry.net.za", response.Registrar.WhoisServer.Value);

        Assert.Equal(new DateTime(2014, 11, 10, 7, 8, 28), response.Updated);
        Assert.Equal(new DateTime(2014, 11, 3, 22, 0, 8), response.Registered);
        Assert.Equal(new DateTime(2015, 11, 3, 22, 0, 8), response.Expiration);
        Assert.Equal("LEX-5FP-22YL", response.Registrant.RegistryId);
        Assert.Equal("Domain Administrator", response.Registrant.Name);
        Assert.Equal("The Car Trader (Pty) Ltd", response.Registrant.Organization);

        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("154 Bram Fischer Drive Randburg", response.Registrant.Address[0]);
        Assert.Equal("Johannesburg", response.Registrant.Address[1]);
        Assert.Equal("2194", response.Registrant.Address[2]);
        Assert.Equal("ZA", response.Registrant.Address[3]);

        Assert.Equal("+27.116860900", response.Registrant.TelephoneNumber);
        Assert.Equal("+27.117896449", response.Registrant.FaxNumber);
        Assert.Equal("domains@autotrader.co.za", response.Registrant.Email);

        Assert.Equal("LEX-5FP-22YL", response.AdminContact.RegistryId);
        Assert.Equal("Domain Administrator", response.AdminContact.Name);
        Assert.Equal("The Car Trader (Pty) Ltd", response.AdminContact.Organization);

        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("154 Bram Fischer Drive Randburg", response.AdminContact.Address[0]);
        Assert.Equal("Johannesburg", response.AdminContact.Address[1]);
        Assert.Equal("2194", response.AdminContact.Address[2]);
        Assert.Equal("ZA", response.AdminContact.Address[3]);

        Assert.Equal("+27.116860900", response.AdminContact.TelephoneNumber);
        Assert.Equal("+27.117896449", response.AdminContact.FaxNumber);
        Assert.Equal("domains@autotrader.co.za", response.AdminContact.Email);

        Assert.Equal("LEX-1-PGD", response.BillingContact.RegistryId);
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

        Assert.Equal("LEX-5FP-22YL", response.TechnicalContact.RegistryId);
        Assert.Equal("Domain Administrator", response.TechnicalContact.Name);
        Assert.Equal("The Car Trader (Pty) Ltd", response.TechnicalContact.Organization);

        Assert.Equal(4, response.TechnicalContact.Address.Count);
        Assert.Equal("154 Bram Fischer Drive Randburg", response.TechnicalContact.Address[0]);
        Assert.Equal("Johannesburg", response.TechnicalContact.Address[1]);
        Assert.Equal("2194", response.TechnicalContact.Address[2]);
        Assert.Equal("ZA", response.TechnicalContact.Address[3]);

        Assert.Equal("+27.116860900", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+27.117896449", response.TechnicalContact.FaxNumber);
        Assert.Equal("domains@autotrader.co.za", response.TechnicalContact.Email);


        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("ns1.lexsynergy.net", response.NameServers[0]);
        Assert.Equal("ns2.lexsynergy.us", response.NameServers[1]);
        Assert.Equal("ns3.lexsynergy.info", response.NameServers[2]);

        Assert.Equal(3, response.DomainStatus.Count);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[1]);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[2]);
    }
}
