using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.SeCom;

public class SeComParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public SeComParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.centralnic.com", "se.com", "not-found", "not_found.txt");
        var response = parser.Parse("whois.centralnic.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.centralnic.com/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.centralnic.com", "se.com", "found", "found.txt");
        var response = parser.Parse("whois.centralnic.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.centralnic.com/found/01", response.TemplateName);

        Assert.Equal("hotel.se.com", response.DomainName.ToString());
        Assert.Equal("CNIC-DO561053", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("InternetX GmbH", response.Registrar.Name);
        Assert.Equal("http://www.internetx.de/", response.Registrar.Url);
        Assert.Equal("+49-941-595590", response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2013, 6, 3, 10, 33, 46, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2008, 5, 10, 5, 17, 32, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2014, 5, 10, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("INX-10599082com", response.Registrant.RegistryId);
        Assert.Equal("Hotel Reservation Service Robert Ragge GmbH", response.Registrant.Name);
        Assert.Equal("Hotel Reservation Service Robert Ragge GmbH", response.Registrant.Organization);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("Blaubach 32", response.Registrant.Address[0]);
        Assert.Equal("Koeln", response.Registrant.Address[1]);
        Assert.Equal("NRW", response.Registrant.Address[2]);
        Assert.Equal("50676", response.Registrant.Address[3]);
        Assert.Equal("DE", response.Registrant.Address[4]);

        Assert.Equal("+49.2212077222", response.Registrant.TelephoneNumber);
        Assert.Equal("domains@hrs.de", response.Registrant.Email);


        // AdminContact Details
        Assert.Equal("INX-201727com", response.AdminContact.RegistryId);
        Assert.Equal("Robert Ragge", response.AdminContact.Name);
        Assert.Equal("Hotel Reservation Service Robert Ragge GmbH", response.AdminContact.Organization);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("Blaubach 32", response.AdminContact.Address[0]);
        Assert.Equal("Koeln", response.AdminContact.Address[1]);
        Assert.Equal("DE", response.AdminContact.Address[2]);
        Assert.Equal("50676", response.AdminContact.Address[3]);
        Assert.Equal("DE", response.AdminContact.Address[4]);

        Assert.Equal("+49.2212077222", response.AdminContact.TelephoneNumber);
        Assert.Equal("domains@hrs.de", response.AdminContact.Email);


        // BillingContact Details
        Assert.Equal("INX-10599082com", response.BillingContact.RegistryId);
        Assert.Equal("Hotel Reservation Service Robert Ragge GmbH", response.BillingContact.Name);
        Assert.Equal("Hotel Reservation Service Robert Ragge GmbH", response.BillingContact.Organization);

        // BillingContact Address
        Assert.Equal(5, response.BillingContact.Address.Count);
        Assert.Equal("Blaubach 32", response.BillingContact.Address[0]);
        Assert.Equal("Koeln", response.BillingContact.Address[1]);
        Assert.Equal("NRW", response.BillingContact.Address[2]);
        Assert.Equal("50676", response.BillingContact.Address[3]);
        Assert.Equal("DE", response.BillingContact.Address[4]);

        Assert.Equal("+49.2212077222", response.BillingContact.TelephoneNumber);
        Assert.Equal("+49.2212077394", response.BillingContact.FaxNumber);
        Assert.Equal("domains@hrs.de", response.BillingContact.Email);


        // TechnicalContact Details
        Assert.Equal("INX-201728com", response.TechnicalContact.RegistryId);
        Assert.Equal("Uwe Watzek", response.TechnicalContact.Name);
        Assert.Equal("Wind Internethaus GmbH", response.TechnicalContact.Organization);

        // TechnicalContact Address
        Assert.Equal(6, response.TechnicalContact.Address.Count);
        Assert.Equal("Am Krebsgraben 15", response.TechnicalContact.Address[0]);
        Assert.Equal("Haus 2", response.TechnicalContact.Address[1]);
        Assert.Equal("Villingen-Schwenningen", response.TechnicalContact.Address[2]);
        Assert.Equal("Baden-Wuerttemberg", response.TechnicalContact.Address[3]);
        Assert.Equal("78048", response.TechnicalContact.Address[4]);
        Assert.Equal("DE", response.TechnicalContact.Address[5]);

        Assert.Equal("+49.77214070740", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("info@windinternethaus.de", response.TechnicalContact.Email);


        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("ns1.hrs.de", response.NameServers[0]);
        Assert.Equal("ns2.hrs.de", response.NameServers[1]);
        Assert.Equal("ns2.surfbrett.de", response.NameServers[2]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal("Unsigned", response.DnsSecStatus);
        Assert.Equal(56, response.FieldsParsed);
    }
}
