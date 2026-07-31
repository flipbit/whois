using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Asia.Asia;

public class AsiaParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public AsiaParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.asia", "asia", "found", "novalash.asia.txt");
        var response = parser.Parse("whois.nic.asia", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.asia/asia/found/01", response.TemplateName);

        Assert.Null(response.DomainName);
        Assert.Equal(" REDACTED", response.RegistryDomainId);

        // Registrar Details
        Assert.Null(response.Registrar);

        Assert.Null(response.Updated);
        Assert.Null(response.Registered);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Equal(" REDACTED", response.Registrant.RegistryId);
        Assert.Equal(" REDACTED", response.Registrant.Name);
        Assert.Equal(" Novalash", response.Registrant.Organization);
        Assert.Null(response.Registrant.TelephoneNumber);
        Assert.Null(response.Registrant.Email);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal(" REDACTED", response.Registrant.Address[0]);
        Assert.Equal(" TX", response.Registrant.Address[1]);
        Assert.Equal(" REDACTED", response.Registrant.Address[2]);


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
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal(9, response.FieldsParsed);
    }

    [Fact]
    public void Test_other_status_single()
    {
        var sample = SampleReader.Read("whois.nic.asia", "asia", "found", "cj7.asia.txt");
        var response = parser.Parse("whois.nic.asia", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.asia/asia/found/01", response.TemplateName);

        Assert.Null(response.DomainName);
        Assert.Equal(" REDACTED", response.RegistryDomainId);

        // Registrar Details
        Assert.Null(response.Registrar);

        Assert.Null(response.Updated);
        Assert.Null(response.Registered);
        Assert.Null(response.Expiration);

        // Registrant Details
        Assert.Equal(" REDACTED", response.Registrant.RegistryId);
        Assert.Equal(" REDACTED", response.Registrant.Name);
        Assert.Equal(" Super Privacy Service LTD c/o Dynadot", response.Registrant.Organization);
        Assert.Null(response.Registrant.TelephoneNumber);
        Assert.Null(response.Registrant.Email);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal(" REDACTED", response.Registrant.Address[0]);
        Assert.Equal(" California", response.Registrant.Address[1]);
        Assert.Equal(" REDACTED", response.Registrant.Address[2]);


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
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);

        Assert.Equal(9, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.asia", "asia", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.asia", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.nic.asia", "asia", "found", "found_status_registered.txt");
        var response = parser.Parse("whois.nic.asia", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.asia/asia/found/01", response.TemplateName);

        Assert.Equal("cj7.asia", response.DomainName.ToString());
        Assert.Equal("D93126-ASIA", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("dotASIA R4-ASIA (800046)", response.Registrar.Name);

        Assert.Equal(new DateTime(2014, 01, 15, 22, 20, 16, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2008, 01, 15, 11, 28, 02, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2015, 01, 15, 11, 28, 02, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("FR-132aa75b4bf65", response.Registrant.RegistryId);
        Assert.Equal("RAXCO ASSETS CORP.", response.Registrant.Name);
        Assert.Equal("RAXCO ASSETS CORP.", response.Registrant.Organization);
        Assert.Equal("+852.21190333", response.Registrant.TelephoneNumber);
        Assert.Equal("+852.23045326", response.Registrant.FaxNumber);
        Assert.Equal("eddie.yeung@bingogroup.com.hk", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("RM 1201-1204 12/F", response.Registrant.Address[0]);
        Assert.Equal("SEA BIRD HSE", response.Registrant.Address[1]);
        Assert.Equal("22-28 WYNDHAM ST CENTRAL HK", response.Registrant.Address[2]);
        Assert.Equal("Hong Kong", response.Registrant.Address[3]);
        Assert.Equal("HK", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("FR-132aa7afe0967", response.AdminContact.RegistryId);
        Assert.Equal(":Eddie Yeung", response.AdminContact.Name);
        Assert.Equal("RAXCO ASSETS CORP.", response.AdminContact.Organization);
        Assert.Equal("+852.21190333", response.AdminContact.TelephoneNumber);
        Assert.Equal("eddie.yeung@bingogroup.com.hk", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("RM 1201-1204 12/F", response.AdminContact.Address[0]);
        Assert.Equal("SEA BIRD HSE", response.AdminContact.Address[1]);
        Assert.Equal("22-28 WYNDHAM ST CENTRAL HK", response.AdminContact.Address[2]);
        Assert.Equal("Hong Kong", response.AdminContact.Address[3]);
        Assert.Equal("HK", response.AdminContact.Address[4]);


        // BillingContact Details
        Assert.Equal("FR-132aa774c1b66", response.BillingContact.RegistryId);
        Assert.Equal("Frankie Chan", response.BillingContact.Name);
        Assert.Equal("RAXCO ASSETS CORP.", response.BillingContact.Organization);
        Assert.Equal("+852.21190333", response.BillingContact.TelephoneNumber);
        Assert.Equal("eddie.yeung@bingogroup.com.hk", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(5, response.BillingContact.Address.Count);
        Assert.Equal("RM 1201-1204 12/F", response.BillingContact.Address[0]);
        Assert.Equal("SEA BIRD HSE", response.BillingContact.Address[1]);
        Assert.Equal("22-28 WYNDHAM ST CENTRAL HK", response.BillingContact.Address[2]);
        Assert.Equal("Hong Kong", response.BillingContact.Address[3]);
        Assert.Equal("HK", response.BillingContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("FR-132aa7afe0967", response.TechnicalContact.RegistryId);
        Assert.Equal("Eddie Yeung", response.TechnicalContact.Name);
        Assert.Equal("RAXCO ASSETS CORP.", response.TechnicalContact.Organization);
        Assert.Equal("+852.21190333", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("eddie.yeung@bingogroup.com.hk", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("RM 1201-1204 12/F", response.TechnicalContact.Address[0]);
        Assert.Equal("SEA BIRD HSE", response.TechnicalContact.Address[1]);
        Assert.Equal("22-28 WYNDHAM ST CENTRAL HK", response.TechnicalContact.Address[2]);
        Assert.Equal("Hong Kong", response.TechnicalContact.Address[3]);
        Assert.Equal("HK", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(6, response.NameServers.Count);
        Assert.Equal("ns1.dnspod.net", response.NameServers[0]);
        Assert.Equal("ns2.dnspod.net", response.NameServers[1]);
        Assert.Equal("ns3.dnspod.net", response.NameServers[2]);
        Assert.Equal("ns4.dnspod.net", response.NameServers[3]);
        Assert.Equal("ns5.dnspod.net", response.NameServers[4]);
        Assert.Equal("ns6.dnspod.net", response.NameServers[5]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("OK", response.DomainStatus[0]);

        Assert.Equal(55, response.FieldsParsed);
    }

    [Fact]
    public void Test_reserved()
    {
        var sample = SampleReader.Read("whois.nic.asia", "asia", "reserved", "reserved.txt");
        var response = parser.Parse("whois.nic.asia", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Reserved, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.asia/asia/reserved/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }
}
