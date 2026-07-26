using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Coop.Coop;

public class CoopParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public CoopParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.coop", "coop", "found", "moscowfood.coop.txt");
        var response = parser.Parse("whois.nic.coop", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("moscowfood.coop", response.DomainName.ToString());
        Assert.Equal("D7879420-CNIC", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("Ascio Technologies, Inc. - Denmark", response.Registrar.Name);
        Assert.Equal("106", response.Registrar.IanaId);

        Assert.Equal(new DateTime(2001, 10, 09, 10, 21, 35, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 01, 30, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.RegistryId);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Name);
        Assert.Equal("Moscow Food Co-op", response.Registrant.Organization);
        Assert.Null(response.Registrant.TelephoneNumber);
        Assert.Null(response.Registrant.FaxNumber);
        Assert.Null(response.Registrant.Email);

        // Registrant Address
        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Address[0]);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Address[1]);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Address[2]);
        Assert.Equal("US", response.Registrant.Address[3]);


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // BillingContact Details
        Assert.Null(response.BillingContact);

        // BillingContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.dotster.com", response.NameServers[0]);
        Assert.Equal("ns2.dotster.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal(23, response.FieldsParsed);
    }

    [Fact]
    public void Test_other_status_single()
    {
        var sample = SampleReader.Read("whois.nic.coop", "coop", "found", "calgary.coop.txt");
        var response = parser.Parse("whois.nic.coop", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("calgary.coop", response.DomainName.ToString());
        Assert.Equal("D7880569-CNIC", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("Domains.coop Limited", response.Registrar.Name);
        Assert.Equal("465", response.Registrar.IanaId);

        Assert.Equal(new DateTime(2002, 01, 31, 10, 21, 44, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 01, 31, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.RegistryId);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Name);
        Assert.Equal("Calgary Co operative Association Limited", response.Registrant.Organization);
        Assert.Null(response.Registrant.TelephoneNumber);
        Assert.Null(response.Registrant.FaxNumber);
        Assert.Null(response.Registrant.Email);

        // Registrant Address
        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Address[0]);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Address[1]);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Address[2]);
        Assert.Equal("CA", response.Registrant.Address[3]);


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // BillingContact Details
        Assert.Null(response.BillingContact);

        // BillingContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.yoursrs.com", response.NameServers[0]);
        Assert.Equal("ns2.yoursrs.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal(22, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.coop", "coop", "not-found", "u34jedzcq.coop.txt");
        var response = parser.Parse("whois.nic.coop", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.coop/coop/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.coop", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.nic.coop", "coop", "found", "found_status_registered.txt");
        var response = parser.Parse("whois.nic.coop", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.coop/coop/found/01", response.TemplateName);

        Assert.Equal("calgary.coop", response.DomainName.ToString());
        Assert.Equal("7441D-COOP", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("domains.coop", response.Registrar.Name);
        Assert.Equal("465", response.Registrar.IanaId);

        Assert.Equal(new DateTime(2002, 01, 31, 22, 12, 44, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2017, 01, 31, 22, 12, 44, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("54100C-COOP", response.Registrant.RegistryId);
        Assert.Equal("Net Admin", response.Registrant.Name);
        Assert.Equal("Calgary Co operative Association Limited", response.Registrant.Organization);
        Assert.Equal("+1.4032196025", response.Registrant.TelephoneNumber);
        Assert.Equal("+1.4032995416", response.Registrant.FaxNumber);
        Assert.Equal("netadmin@calgarycoop.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("2735 39 Avenue NE", response.Registrant.Address[0]);
        Assert.Equal("Calgary", response.Registrant.Address[1]);
        Assert.Equal("AB", response.Registrant.Address[2]);
        Assert.Equal("T1Y 7C7", response.Registrant.Address[3]);
        Assert.Equal("Canada", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("54100C-COOP", response.AdminContact.RegistryId);
        Assert.Equal("Net Admin", response.AdminContact.Name);
        Assert.Equal("Calgary Co operative Association Limited", response.AdminContact.Organization);
        Assert.Equal("+1.4032196025", response.AdminContact.TelephoneNumber);
        Assert.Equal("+1.4032995416", response.AdminContact.FaxNumber);
        Assert.Equal("netadmin@calgarycoop.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("2735 39 Avenue NE", response.AdminContact.Address[0]);
        Assert.Equal("Calgary", response.AdminContact.Address[1]);
        Assert.Equal("AB", response.AdminContact.Address[2]);
        Assert.Equal("T1Y 7C7", response.AdminContact.Address[3]);
        Assert.Equal("Canada", response.AdminContact.Address[4]);


        // BillingContact Details
        Assert.Equal("54100C-COOP", response.BillingContact.RegistryId);
        Assert.Equal("Net Admin", response.BillingContact.Name);
        Assert.Equal("Calgary Co operative Association Limited", response.BillingContact.Organization);
        Assert.Equal("+1.4032196025", response.BillingContact.TelephoneNumber);
        Assert.Equal("+1.4032995416", response.BillingContact.FaxNumber);
        Assert.Equal("netadmin@calgarycoop.com", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(5, response.BillingContact.Address.Count);
        Assert.Equal("2735 39 Avenue NE", response.BillingContact.Address[0]);
        Assert.Equal("Calgary", response.BillingContact.Address[1]);
        Assert.Equal("AB", response.BillingContact.Address[2]);
        Assert.Equal("T1Y 7C7", response.BillingContact.Address[3]);
        Assert.Equal("Canada", response.BillingContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("54100C-COOP", response.TechnicalContact.RegistryId);
        Assert.Equal("Net Admin", response.TechnicalContact.Name);
        Assert.Equal("Calgary Co operative Association Limited", response.TechnicalContact.Organization);
        Assert.Equal("+1.4032196025", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+1.4032995416", response.TechnicalContact.FaxNumber);
        Assert.Equal("netadmin@calgarycoop.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("2735 39 Avenue NE", response.TechnicalContact.Address[0]);
        Assert.Equal("Calgary", response.TechnicalContact.Address[1]);
        Assert.Equal("AB", response.TechnicalContact.Address[2]);
        Assert.Equal("T1Y 7C7", response.TechnicalContact.Address[3]);
        Assert.Equal("Canada", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.calgarycoop.net", response.NameServers[0]);
        Assert.Equal("ns2.calgarycoop.net", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal(58, response.FieldsParsed);
    }
}
