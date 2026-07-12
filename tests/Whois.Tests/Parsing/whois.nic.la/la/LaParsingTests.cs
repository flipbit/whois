using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.La.La;

public class LaParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public LaParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.la", "la", "found", "plasticsurgery.la.txt");
        var response = parser.Parse("whois.nic.la", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/02", response.TemplateName);

        Assert.Equal("plasticsurgery.la", response.DomainName.ToString());
        Assert.Equal("D469366-LANIC", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("+1.4805058800", response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2026, 02, 03, 17, 02, 11, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2004, 02, 02, 01, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 02, 02, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


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
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns-1470.awsdns-55.org", response.NameServers[0]);
        Assert.Equal("ns-264.awsdns-33.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(4, response.DomainStatus.Count);
        Assert.Equal("clientRenewProhibited", response.DomainStatus[0]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[1]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(18, response.FieldsParsed);
    }

    [Fact]
    public void Test_other_status_single()
    {
        var sample = SampleReader.Read("whois.nic.la", "la", "found", "google.la.txt");
        var response = parser.Parse("whois.nic.la", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/02", response.TemplateName);

        Assert.Equal("google.la", response.DomainName.ToString());
        Assert.Equal("D471480-LANIC", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("+44.20338806", response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2026, 06, 16, 19, 39, 04, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2002, 07, 18, 01, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 07, 18, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


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
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);

        Assert.Equal(15, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.la", "la", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.la", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.nic.la", "la", "found", "found_status_registered.txt");
        var response = parser.Parse("whois.nic.la", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.la", response.DomainName.ToString());
        Assert.Equal("CNIC-DO471480", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("1564", response.Registrar.IanaId);
        Assert.Equal("020 33 88 0600", response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2013, 08, 01, 15, 09, 21, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2002, 07, 18, 01, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2014, 07, 18, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("ndn-96955", response.Registrant.RegistryId);
        Assert.Equal("Google Inc", response.Registrant.Name);
        Assert.Equal("Google Inc", response.Registrant.Organization);
        Assert.Equal("+1.6502530000", response.Registrant.TelephoneNumber);
        Assert.Equal("+1.65067188571", response.Registrant.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
        Assert.Equal("Mountain View", response.Registrant.Address[1]);
        Assert.Equal("Ca", response.Registrant.Address[2]);
        Assert.Equal("94043", response.Registrant.Address[3]);
        Assert.Equal("US", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("ndn-96955", response.AdminContact.RegistryId);
        Assert.Equal("Google Inc", response.AdminContact.Name);
        Assert.Equal("Google Inc", response.AdminContact.Organization);
        Assert.Equal("+1.6502530000", response.AdminContact.TelephoneNumber);
        Assert.Equal("+1.65067188571", response.AdminContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
        Assert.Equal("Mountain View", response.AdminContact.Address[1]);
        Assert.Equal("Ca", response.AdminContact.Address[2]);
        Assert.Equal("94043", response.AdminContact.Address[3]);
        Assert.Equal("US", response.AdminContact.Address[4]);


        // BillingContact Details
        Assert.Equal("LAREG-4FB6D5852C61F054", response.BillingContact.RegistryId);
        Assert.Equal("MarkMonitor, Inc.", response.BillingContact.Name);
        Assert.Equal("MarkMonitor, Inc.", response.BillingContact.Organization);
        Assert.Equal("+1.2083895740", response.BillingContact.TelephoneNumber);
        Assert.Equal("+1.2083895771", response.BillingContact.FaxNumber);
        Assert.Equal("ccopsbilling@markmonitor.com", response.BillingContact.Email);

        // BillingContact Address
        Assert.Equal(5, response.BillingContact.Address.Count);
        Assert.Equal("391 N Ancestor Place", response.BillingContact.Address[0]);
        Assert.Equal("Boise", response.BillingContact.Address[1]);
        Assert.Equal("ID", response.BillingContact.Address[2]);
        Assert.Equal("83704", response.BillingContact.Address[3]);
        Assert.Equal("US", response.BillingContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("ndn-96955", response.TechnicalContact.RegistryId);
        Assert.Equal("Google Inc", response.TechnicalContact.Name);
        Assert.Equal("Google Inc", response.TechnicalContact.Organization);
        Assert.Equal("+1.6502530000", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+1.65067188571", response.TechnicalContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
        Assert.Equal("Mountain View", response.TechnicalContact.Address[1]);
        Assert.Equal("Ca", response.TechnicalContact.Address[2]);
        Assert.Equal("94043", response.TechnicalContact.Address[3]);
        Assert.Equal("US", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(2, response.DomainStatus.Count);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);
        Assert.Equal("serverTransferProhibited", response.DomainStatus[1]);

        Assert.Equal("Unsigned", response.DnsSecStatus);
        Assert.Equal(59, response.FieldsParsed);
    }
}
