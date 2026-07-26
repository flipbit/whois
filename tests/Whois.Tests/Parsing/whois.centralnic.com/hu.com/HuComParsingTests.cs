using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.HuCom;

public class HuComParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public HuComParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.centralnic.com", "hu.com", "found", "found.txt");
        var response = parser.Parse("whois.centralnic.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.centralnic.com/found/01", response.TemplateName);

        Assert.Equal("hotel.hu.com", response.DomainName.ToString());
        Assert.Equal("CNIC-DO482594", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("Domain Exploitation International", response.Registrar.Name);

        // Registrant Details
        Assert.Equal("H1088667", response.Registrant.RegistryId);

        // AdminContact Details
        Assert.Equal("H122681", response.AdminContact.RegistryId);

        // BillingContact Details
        Assert.Equal("H1088667", response.BillingContact.RegistryId);

        // TechnicalContact Details
        Assert.Equal("H122681", response.TechnicalContact.RegistryId);

        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.domain-exploitation.us.com", response.NameServers[0]);
        Assert.Equal("ns2.domain-exploitation.us.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("OK", response.DomainStatus[0]);

        Assert.Equal("Unsigned", response.DnsSecStatus);
        Assert.Equal(12, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.centralnic.com", "hu.com", "not-found", "not_found.txt");
        var response = parser.Parse("whois.centralnic.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.centralnic.com/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.centralnic.com", "hu.com", "found", "found_status_registered.txt");
        var response = parser.Parse("whois.centralnic.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.PendingDelete, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.centralnic.com/found/01", response.TemplateName);

        Assert.Equal("porn.hu.com", response.DomainName.ToString());
        Assert.Equal("CNIC-DO970405", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("101Domain, Inc.", response.Registrar.Name);
        Assert.Equal("http://www.101domain.com", response.Registrar.Url);
        Assert.Equal("+1.7604448674", response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2014, 2, 11, 0, 16, 13, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2012, 11, 28, 17, 46, 3, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2013, 11, 28, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("RWG000000004273D", response.Registrant.RegistryId);
        Assert.Equal("Gintautas Liaskus", response.Registrant.Name);
        Assert.Equal("G.Liaskaus firma INFOMEGA", response.Registrant.Organization);

        // Registrant Address
        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("Kapsu 32-53", response.Registrant.Address[0]);
        Assert.Equal("Vilnius", response.Registrant.Address[1]);
        Assert.Equal("02167", response.Registrant.Address[2]);
        Assert.Equal("LT", response.Registrant.Address[3]);

        Assert.Equal("+370.52711457", response.Registrant.TelephoneNumber);
        Assert.Equal("infotau@infotau.lt", response.Registrant.Email);

        // AdminContact Details
        Assert.Equal("RWG000000004273D", response.AdminContact.RegistryId);
        Assert.Equal("Gintautas Liaskus", response.AdminContact.Name);
        Assert.Equal("G.Liaskaus firma INFOMEGA", response.AdminContact.Organization);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("Kapsu 32-53", response.AdminContact.Address[0]);
        Assert.Equal("Vilnius", response.AdminContact.Address[1]);
        Assert.Equal("02167", response.AdminContact.Address[2]);
        Assert.Equal("LT", response.AdminContact.Address[3]);

        Assert.Equal("+370.52711457", response.AdminContact.TelephoneNumber);
        Assert.Equal("infotau@infotau.lt", response.AdminContact.Email);

        // BillingContact Details
        Assert.Equal("RWG000000004273E", response.BillingContact.RegistryId);
        Assert.Equal("Billing Department", response.BillingContact.Name);
        Assert.Equal("101Domain, Inc.", response.BillingContact.Organization);

        // BillingContact Address
        Assert.Equal(5, response.BillingContact.Address.Count);
        Assert.Equal("5858 Edison Pl.", response.BillingContact.Address[0]);
        Assert.Equal("Carlsbad", response.BillingContact.Address[1]);
        Assert.Equal("CA", response.BillingContact.Address[2]);
        Assert.Equal("92008", response.BillingContact.Address[3]);
        Assert.Equal("US", response.BillingContact.Address[4]);

        Assert.Equal("+1.7604448674", response.BillingContact.TelephoneNumber);
        Assert.Equal("+1.7605794996", response.BillingContact.FaxNumber);
        Assert.Equal("tech1@101domain.com", response.BillingContact.Email);

        // TechnicalContact Details
        Assert.Equal("RWG000000004273D", response.TechnicalContact.RegistryId);
        Assert.Equal("Gintautas Liaskus", response.TechnicalContact.Name);
        Assert.Equal("G.Liaskaus firma INFOMEGA", response.TechnicalContact.Organization);

        // TechnicalContact Address
        Assert.Equal(4, response.TechnicalContact.Address.Count);
        Assert.Equal("Kapsu 32-53", response.TechnicalContact.Address[0]);
        Assert.Equal("Vilnius", response.TechnicalContact.Address[1]);
        Assert.Equal("02167", response.TechnicalContact.Address[2]);
        Assert.Equal("LT", response.TechnicalContact.Address[3]);

        Assert.Equal("+370.52711457", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("infotau@infotau.lt", response.TechnicalContact.Email);

        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.sedoparking.com", response.NameServers[0]);
        Assert.Equal("ns2.sedoparking.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(2, response.DomainStatus.Count);
        Assert.Equal("pendingDelete", response.DomainStatus[0]);
        Assert.Equal("pendingDelete", response.DomainStatus[1]);

        Assert.Equal("Unsigned", response.DnsSecStatus);
        Assert.Equal(53, response.FieldsParsed);
    }
}
