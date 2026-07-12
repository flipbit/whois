using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Co.Co;

public class CoParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public CoParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.co", "co", "not-found", "u34jedzcq.co.txt");
        var response = parser.Parse("whois.nic.co", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.co/co/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.co", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.co", "co", "found", "t.co.txt");
        var response = parser.Parse("whois.nic.co", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        AssertWriter.Write(response);
        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.co/co/found/01", response.TemplateName);

        Assert.Equal("t.co", response.DomainName.ToString());
        Assert.Equal("D740225-CO", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("CSC CORPORATE DOMAINS", response.Registrar.Name);
        Assert.Equal("299", response.Registrar.IanaId);
        Assert.Equal("whois.corporatedomains.com", response.Registrar.Url);

        Assert.Equal(new DateTime(2013, 10, 14, 13, 03, 24, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2010, 04, 26, 07, 50, 40, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2016, 04, 25, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("365684910586C791", response.Registrant.RegistryId);
        Assert.Equal("Twitter, Inc.", response.Registrant.Name);
        Assert.Equal("Twitter, Inc.", response.Registrant.Organization);
        Assert.Equal("+1.4152229670", response.Registrant.TelephoneNumber);
        Assert.Equal("+1.4152220922", response.Registrant.FaxNumber);
        Assert.Equal("domains@twitter.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(7, response.Registrant.Address.Count);
        Assert.Equal("1355 Market Street", response.Registrant.Address[0]);
        Assert.Equal("Suite 900", response.Registrant.Address[1]);
        Assert.Equal("San Francisco", response.Registrant.Address[2]);
        Assert.Equal("CA", response.Registrant.Address[3]);
        Assert.Equal("94103", response.Registrant.Address[4]);
        Assert.Equal("United States", response.Registrant.Address[5]);
        Assert.Equal("US", response.Registrant.Address[6]);


        // AdminContact Details
        Assert.Equal("868543810568A633", response.AdminContact.RegistryId);
        Assert.Equal("Domain Admin", response.AdminContact.Name);
        Assert.Equal("Twitter, Inc.", response.AdminContact.Organization);
        Assert.Equal("+1.4152229670", response.AdminContact.TelephoneNumber);
        Assert.Equal("+1.4152220922", response.AdminContact.FaxNumber);
        Assert.Equal("domains@twitter.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(7, response.AdminContact.Address.Count);
        Assert.Equal("1355 Market Street", response.AdminContact.Address[0]);
        Assert.Equal("Suite 900", response.AdminContact.Address[1]);
        Assert.Equal("San Francisco", response.AdminContact.Address[2]);
        Assert.Equal("California", response.AdminContact.Address[3]);
        Assert.Equal("94103", response.AdminContact.Address[4]);
        Assert.Equal("United States", response.AdminContact.Address[5]);
        Assert.Equal("US", response.AdminContact.Address[6]);


        // BillingContact Details
        Assert.Equal("341112710590A136", response.BillingContact.RegistryId);
        Assert.Equal("ccTLD Billing", response.BillingContact.Name);
        Assert.Equal("CSC Corporate Domains, Inc.", response.BillingContact.Organization);
        Assert.Equal("+1.3026365400", response.BillingContact.TelephoneNumber);
        Assert.Equal("+1.3026365454", response.BillingContact.FaxNumber);
        Assert.Equal("ccTLD-billing@cscinfo.com", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(6, response.BillingContact.Address.Count);
        Assert.Equal("2711 Centerville Rd.", response.BillingContact.Address[0]);
        Assert.Equal("Wilmington", response.BillingContact.Address[1]);
        Assert.Equal("DE", response.BillingContact.Address[2]);
        Assert.Equal("19808", response.BillingContact.Address[3]);
        Assert.Equal("United States", response.BillingContact.Address[4]);
        Assert.Equal("US", response.BillingContact.Address[5]);


        // TechnicalContact Details
        Assert.Equal("42101611057C7478", response.TechnicalContact.RegistryId);
        Assert.Equal("Tech Admin", response.TechnicalContact.Name);
        Assert.Equal("Twitter, Inc.", response.TechnicalContact.Organization);
        Assert.Equal("+1.4152229670", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+1.4152220922", response.TechnicalContact.FaxNumber);
        Assert.Equal("domains-tech@twitter.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(7, response.TechnicalContact.Address.Count);
        Assert.Equal("1355 Market Street", response.TechnicalContact.Address[0]);
        Assert.Equal("Suite 900", response.TechnicalContact.Address[1]);
        Assert.Equal("San Francisco", response.TechnicalContact.Address[2]);
        Assert.Equal("California", response.TechnicalContact.Address[3]);
        Assert.Equal("94103", response.TechnicalContact.Address[4]);
        Assert.Equal("United States", response.TechnicalContact.Address[5]);
        Assert.Equal("US", response.TechnicalContact.Address[6]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.p34.dynect.net", response.NameServers[0]);
        Assert.Equal("ns2.p34.dynect.net", response.NameServers[1]);
        Assert.Equal("ns3.p34.dynect.net", response.NameServers[2]);
        Assert.Equal("ns4.p34.dynect.net", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);

        Assert.Equal(66, response.FieldsParsed);
    }
}
