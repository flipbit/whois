using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.RuCom;

public class RuComParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public RuComParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.centralnic.com", "ru.com", "not-found", "not_found.txt");
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
        var sample = SampleReader.Read("whois.centralnic.com", "ru.com", "found", "found.txt");
        var response = parser.Parse("whois.centralnic.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.centralnic.com/found/01", response.TemplateName);

        Assert.Equal("srk.ru.com", response.DomainName.ToString());
        Assert.Equal("CNIC-DO450826", response.RegistryDomainId);

        Assert.Equal(new DateTime(2012, 7, 10, 8, 16, 19, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2006, 7, 31, 10, 6, 4, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2014, 7, 31, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("H1037013", response.Registrant.RegistryId);
        Assert.Equal("Anthony Lloyd, SRK Consulting (UK) Limited", response.Registrant.Name);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("5th Floor", response.Registrant.Address[0]);
        Assert.Equal("Churchill House", response.Registrant.Address[1]);
        Assert.Equal("Cardiff", response.Registrant.Address[2]);
        Assert.Equal("CF10 2HH", response.Registrant.Address[3]);
        Assert.Equal("GB", response.Registrant.Address[4]);

        Assert.Equal("+44.2920348150", response.Registrant.TelephoneNumber);
        Assert.Equal("alloyd@srk.co.uk", response.Registrant.Email);


        // AdminContact Details
        Assert.Equal("H265405", response.AdminContact.RegistryId);
        Assert.Equal("Anthony Lloyd", response.AdminContact.Name);
        Assert.Equal("SRK Consulting (UK) Limited", response.AdminContact.Organization);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("5th Floor", response.AdminContact.Address[0]);
        Assert.Equal("Churchill House", response.AdminContact.Address[1]);
        Assert.Equal("Cardiff", response.AdminContact.Address[2]);
        Assert.Equal("CF10 2HH", response.AdminContact.Address[3]);
        Assert.Equal("GB", response.AdminContact.Address[4]);

        Assert.Equal("+44.2920348150", response.AdminContact.TelephoneNumber);
        Assert.Equal("alloyd@srk.co.uk", response.AdminContact.Email);


        // BillingContact Details
        Assert.Equal("H265406", response.BillingContact.RegistryId);
        Assert.Equal("A R Lloyd", response.BillingContact.Name);
        Assert.Equal("SRK Consulting (UK) Limited", response.BillingContact.Organization);

        // BillingContact Address
        Assert.Equal(3, response.BillingContact.Address.Count);
        Assert.Equal("Windsor Court", response.BillingContact.Address[0]);
        Assert.Equal("CF10 3BX", response.BillingContact.Address[1]);
        Assert.Equal("GB", response.BillingContact.Address[2]);

        Assert.Equal("+44.2920348150", response.BillingContact.TelephoneNumber);
        Assert.Equal("alloyd@srk.co.uk", response.BillingContact.Email);


        // TechnicalContact Details
        Assert.Equal("H265405", response.TechnicalContact.RegistryId);
        Assert.Equal("Anthony Lloyd", response.TechnicalContact.Name);
        Assert.Equal("SRK Consulting (UK) Limited", response.TechnicalContact.Organization);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("5th Floor", response.TechnicalContact.Address[0]);
        Assert.Equal("Churchill House", response.TechnicalContact.Address[1]);
        Assert.Equal("Cardiff", response.TechnicalContact.Address[2]);
        Assert.Equal("CF10 2HH", response.TechnicalContact.Address[3]);
        Assert.Equal("GB", response.TechnicalContact.Address[4]);

        Assert.Equal("+44.2920348150", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("alloyd@srk.co.uk", response.TechnicalContact.Email);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns7.zoneedit.com", response.NameServers[0]);
        Assert.Equal("ns12.zoneedit.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal("Unsigned", response.DnsSecStatus);
        Assert.Equal(47, response.FieldsParsed);
    }
}
