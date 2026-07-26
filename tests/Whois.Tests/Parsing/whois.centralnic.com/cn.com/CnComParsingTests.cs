using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.CnCom;

public class CnComParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public CnComParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.centralnic.com", "cn.com", "not-found", "not_found.txt");
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
        var sample = SampleReader.Read("whois.centralnic.com", "cn.com", "found", "found.txt");
        var response = parser.Parse("whois.centralnic.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.centralnic.com/found/01", response.TemplateName);

        Assert.Equal("gsn.cn.com", response.DomainName.ToString());
        Assert.Equal("CNIC-DO323367", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("united-domains AG", response.Registrar.Name);
        Assert.Equal("http://www.united-domains.de", response.Registrar.Url);
        Assert.Equal("+498151368670", response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2013, 11, 26, 12, 16, 45, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2005, 11, 23, 15, 44, 3, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2014, 11, 23, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("H1062079", response.Registrant.RegistryId);
        Assert.Equal("GSN Electronics Incorporation Pte Ltd", response.Registrant.Name);

        // Registrant Address
        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("Straits Trading Building 9 Battery Road 16-08", response.Registrant.Address[0]);
        Assert.Equal("Singapore", response.Registrant.Address[1]);
        Assert.Equal("049910", response.Registrant.Address[2]);
        Assert.Equal("SG", response.Registrant.Address[3]);

        Assert.Equal("+65.62336919", response.Registrant.TelephoneNumber);
        Assert.Equal("abuse@gsn.in", response.Registrant.Email);


        // AdminContact Details
        Assert.Equal("AUTO-DRZK-SNVHSY", response.AdminContact.RegistryId);
        Assert.Equal("Pauline Ang", response.AdminContact.Name);
        Assert.Equal("GSN Electronics Incorporation Pte Ltd", response.AdminContact.Organization);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("Straits Trading Building 9 Battery Road 16-08", response.AdminContact.Address[0]);
        Assert.Equal("Singapore", response.AdminContact.Address[1]);
        Assert.Equal("049910", response.AdminContact.Address[2]);
        Assert.Equal("SG", response.AdminContact.Address[3]);

        Assert.Equal("+65.62336919", response.AdminContact.TelephoneNumber);
        Assert.Equal("abuse@gsn.in", response.AdminContact.Email);


        // BillingContact Details
        Assert.Equal("C-UHM65D7-TJGULR", response.BillingContact.RegistryId);
        Assert.Equal("Host Master", response.BillingContact.Name);
        Assert.Equal("united-domains AG", response.BillingContact.Organization);

        // BillingContact Address
        Assert.Equal(5, response.BillingContact.Address.Count);
        Assert.Equal("Gautinger Str. 10", response.BillingContact.Address[0]);
        Assert.Equal("Starnberg", response.BillingContact.Address[1]);
        Assert.Equal("Bayern", response.BillingContact.Address[2]);
        Assert.Equal("82319", response.BillingContact.Address[3]);
        Assert.Equal("DE", response.BillingContact.Address[4]);

        Assert.Equal("+49.8151368670", response.BillingContact.TelephoneNumber);
        Assert.Equal("+49.81513686777", response.BillingContact.FaxNumber);
        Assert.Equal("hostmaster@united-domains.de", response.BillingContact.Email);


        // TechnicalContact Details
        Assert.Equal("C-UHM65D7-TJGULR", response.TechnicalContact.RegistryId);
        Assert.Equal("Host Master", response.TechnicalContact.Name);
        Assert.Equal("united-domains AG", response.TechnicalContact.Organization);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("Gautinger Str. 10", response.TechnicalContact.Address[0]);
        Assert.Equal("Starnberg", response.TechnicalContact.Address[1]);
        Assert.Equal("Bayern", response.TechnicalContact.Address[2]);
        Assert.Equal("82319", response.TechnicalContact.Address[3]);
        Assert.Equal("DE", response.TechnicalContact.Address[4]);

        Assert.Equal("+49.8151368670", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("hostmaster@united-domains.de", response.TechnicalContact.Email);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.meteos.it", response.NameServers[0]);
        Assert.Equal("ns2.meteos.it", response.NameServers[1]);

        // Domain Status
        Assert.Equal(2, response.DomainStatus.Count);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);
        Assert.Equal("serverTransferProhibited", response.DomainStatus[1]);

        Assert.Equal("Unsigned", response.DnsSecStatus);
        Assert.Equal(53, response.FieldsParsed);
    }
}
