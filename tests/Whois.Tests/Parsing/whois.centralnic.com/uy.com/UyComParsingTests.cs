using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.UyCom;

public class UyComParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public UyComParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.centralnic.com", "uy.com", "found", "found.txt");
        var response = parser.Parse("whois.centralnic.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.centralnic.com/found/01", response.TemplateName);

        Assert.Equal("bingo.uy.com", response.DomainName.ToString());
        Assert.Equal("CNIC-DO705337", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("Domain Exploitation International", response.Registrar.Name);


        // Registrant Details
        Assert.Equal("H122681", response.Registrant.RegistryId);


        // AdminContact Details
        Assert.Equal("H122681", response.AdminContact.RegistryId);


        // BillingContact Details
        Assert.Equal("H122681", response.BillingContact.RegistryId);


        // TechnicalContact Details
        Assert.Equal("H122681", response.TechnicalContact.RegistryId);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns2.domain-exploitation.us.com", response.NameServers[0]);
        Assert.Equal("ns1.domain-exploitation.us.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("OK", response.DomainStatus[0]);

        Assert.Equal("Unsigned", response.DnsSecStatus);
        Assert.Equal(12, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.centralnic.com", "uy.com", "not-found", "not_found.txt");
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
        var sample = SampleReader.Read("whois.centralnic.com", "uy.com", "found", "found_status_registered.txt");
        var response = parser.Parse("whois.centralnic.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.centralnic.com/found/01", response.TemplateName);

        Assert.Equal("bestb.uy.com", response.DomainName.ToString());
        Assert.Equal("CNIC-DO493832", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("Webfusion", response.Registrar.Name);
        Assert.Equal("1515", response.Registrar.IanaId);
        Assert.Equal("http://www.123-reg.co.uk/domain-names/", response.Registrar.Url);
        Assert.Equal("0845 859 0018", response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2013, 7, 10, 0, 27, 20, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2007, 7, 12, 13, 49, 25, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2015, 7, 12, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("MNT32524959440", response.Registrant.RegistryId);
        Assert.Equal("Identity Protection Service", response.Registrant.Name);
        Assert.Equal("Identity Protect Limited", response.Registrant.Organization);
        Assert.Equal("+44.1483307527", response.Registrant.TelephoneNumber);
        Assert.Equal("bestb.uy.com@identity-protect.org", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("PO Box 795", response.Registrant.Address[0]);
        Assert.Equal("Godalming", response.Registrant.Address[1]);
        Assert.Equal("Surrey", response.Registrant.Address[2]);
        Assert.Equal("GU7 9GA", response.Registrant.Address[3]);
        Assert.Equal("GB", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("MNT32524959440", response.AdminContact.RegistryId);
        Assert.Equal("Identity Protection Service", response.AdminContact.Name);
        Assert.Equal("Identity Protect Limited", response.AdminContact.Organization);
        Assert.Equal("+44.1483307527", response.AdminContact.TelephoneNumber);
        Assert.Equal("bestb.uy.com@identity-protect.org", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("PO Box 795", response.AdminContact.Address[0]);
        Assert.Equal("Godalming", response.AdminContact.Address[1]);
        Assert.Equal("Surrey", response.AdminContact.Address[2]);
        Assert.Equal("GU7 9GA", response.AdminContact.Address[3]);
        Assert.Equal("GB", response.AdminContact.Address[4]);


        // BillingContact Details
        Assert.Equal("MNT32524959440", response.BillingContact.RegistryId);
        Assert.Equal("Identity Protection Service", response.BillingContact.Name);
        Assert.Equal("Identity Protect Limited", response.BillingContact.Organization);
        Assert.Equal("+44.1483307527", response.BillingContact.TelephoneNumber);
        Assert.Equal("+44.1483304031", response.BillingContact.FaxNumber);
        Assert.Equal("bestb.uy.com@identity-protect.org", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(5, response.BillingContact.Address.Count);
        Assert.Equal("PO Box 795", response.BillingContact.Address[0]);
        Assert.Equal("Godalming", response.BillingContact.Address[1]);
        Assert.Equal("Surrey", response.BillingContact.Address[2]);
        Assert.Equal("GU7 9GA", response.BillingContact.Address[3]);
        Assert.Equal("GB", response.BillingContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("MNT32524959440", response.TechnicalContact.RegistryId);
        Assert.Equal("Identity Protection Service", response.TechnicalContact.Name);
        Assert.Equal("Identity Protect Limited", response.TechnicalContact.Organization);
        Assert.Equal("+44.1483307527", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("bestb.uy.com@identity-protect.org", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("PO Box 795", response.TechnicalContact.Address[0]);
        Assert.Equal("Godalming", response.TechnicalContact.Address[1]);
        Assert.Equal("Surrey", response.TechnicalContact.Address[2]);
        Assert.Equal("GU7 9GA", response.TechnicalContact.Address[3]);
        Assert.Equal("GB", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns2.123-reg.co.uk", response.NameServers[0]);
        Assert.Equal("ns.123-reg.co.uk", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal("Unsigned", response.DnsSecStatus);
        Assert.Equal(55, response.FieldsParsed);
    }
}
