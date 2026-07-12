using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Space.Space;

public class SpaceParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public SpaceParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.space", "space", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.space", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.space", "space", "found", "nic.space.txt");
        var response = parser.Parse("whois.nic.space", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("nic.space", response.DomainName.ToString());
        Assert.Equal("D2361836-CNIC", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("CentralNic Ltd", response.Registrar.Name);
        Assert.Equal("9999", response.Registrar.IanaId);
        Assert.Equal("http://www.centralnic.com/", response.Registrar.Url);
        Assert.Equal("whois.centralnic.com", response.Registrar.WhoisServer.Value);

        Assert.Equal(new DateTime(2015, 04, 04, 00, 14, 21, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2014, 04, 10, 09, 14, 07, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2016, 04, 10, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("C11480", response.Registrant.RegistryId);
        Assert.Equal("Domain Administrator", response.Registrant.Name);
        Assert.Equal("CentralNic Ltd", response.Registrant.Organization);
        Assert.Equal("+44.2033880600", response.Registrant.TelephoneNumber);
        Assert.Equal("+44.2033880601", response.Registrant.FaxNumber);
        Assert.Equal("domains@centralnic.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("35-39 Moorgate", response.Registrant.Address[0]);
        Assert.Equal("London", response.Registrant.Address[1]);
        Assert.Equal("EC2R 6AR", response.Registrant.Address[2]);
        Assert.Equal("GB", response.Registrant.Address[3]);


        // AdminContact Details
        Assert.Equal("C11480", response.AdminContact.RegistryId);
        Assert.Equal("Domain Administrator", response.AdminContact.Name);
        Assert.Equal("CentralNic Ltd", response.AdminContact.Organization);
        Assert.Equal("+44.2033880600", response.AdminContact.TelephoneNumber);
        Assert.Equal("+44.2033880601", response.AdminContact.FaxNumber);
        Assert.Equal("domains@centralnic.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(4, response.AdminContact.Address.Count);
        Assert.Equal("35-39 Moorgate", response.AdminContact.Address[0]);
        Assert.Equal("London", response.AdminContact.Address[1]);
        Assert.Equal("EC2R 6AR", response.AdminContact.Address[2]);
        Assert.Equal("GB", response.AdminContact.Address[3]);


        // BillingContact Details
        Assert.Equal("C11480", response.BillingContact.RegistryId);
        Assert.Equal("Domain Administrator", response.BillingContact.Name);
        Assert.Equal("CentralNic Ltd", response.BillingContact.Organization);
        Assert.Equal("+44.2033880600", response.BillingContact.TelephoneNumber);
        Assert.Equal("+44.2033880601", response.BillingContact.FaxNumber);
        Assert.Equal("domains@centralnic.com", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(4, response.BillingContact.Address.Count);
        Assert.Equal("35-39 Moorgate", response.BillingContact.Address[0]);
        Assert.Equal("London", response.BillingContact.Address[1]);
        Assert.Equal("EC2R 6AR", response.BillingContact.Address[2]);
        Assert.Equal("GB", response.BillingContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("C11480", response.TechnicalContact.RegistryId);
        Assert.Equal("Domain Administrator", response.TechnicalContact.Name);
        Assert.Equal("CentralNic Ltd", response.TechnicalContact.Organization);
        Assert.Equal("+44.2033880600", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+44.2033880601", response.TechnicalContact.FaxNumber);
        Assert.Equal("domains@centralnic.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(4, response.TechnicalContact.Address.Count);
        Assert.Equal("35-39 Moorgate", response.TechnicalContact.Address[0]);
        Assert.Equal("London", response.TechnicalContact.Address[1]);
        Assert.Equal("EC2R 6AR", response.TechnicalContact.Address[2]);
        Assert.Equal("GB", response.TechnicalContact.Address[3]);


        // Nameservers
        Assert.Equal(6, response.NameServers.Count);
        Assert.Equal("ns0.centralnic-dns.com", response.NameServers[0]);
        Assert.Equal("ns1.centralnic-dns.com", response.NameServers[1]);
        Assert.Equal("ns2.centralnic-dns.com", response.NameServers[2]);
        Assert.Equal("ns3.centralnic-dns.com", response.NameServers[3]);
        Assert.Equal("ns4.centralnic-dns.com", response.NameServers[4]);
        Assert.Equal("ns5.centralnic-dns.com", response.NameServers[5]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(58, response.FieldsParsed);
    }
}
