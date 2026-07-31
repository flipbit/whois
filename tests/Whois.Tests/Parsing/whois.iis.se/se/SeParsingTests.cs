using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Iis.Se.Se;

public class SeParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public SeParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.iis.se", "se", "found", "found.txt");
        var response = parser.Parse("whois.iis.se", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.iis.se/se/found/01", response.TemplateName);

        Assert.Equal("populiscreate.se", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("EuroDNS S.A", response.Registrar.Name);

        Assert.Equal(new DateTime(2010, 08, 05, 00, 00, 00, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2011, 08, 05, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("eds1008-4130626", response.Registrant.RegistryId);


        // AdminContact Details
        Assert.Equal("eds0903-00001", response.AdminContact.RegistryId);


        // BillingContact Details
        Assert.Equal("eds0903-00001", response.BillingContact.RegistryId);


        // TechnicalContact Details
        Assert.Equal("eds0903-00002", response.TechnicalContact.RegistryId);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns2.eurodns.com", response.NameServers[0]);
        Assert.Equal("ns1.eurodns.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("active", response.DomainStatus[0]);

        Assert.Equal("unsigned delegation", response.DnsSecStatus);
        Assert.Equal(13, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_nameservers_single()
    {
        var sample = SampleReader.Read("whois.iis.se", "se", "found", "nhv.se.txt");
        var response = parser.Parse("whois.iis.se", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.iis.se/se/found/01", response.TemplateName);

        Assert.Equal("nhv.se", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("INLEED", response.Registrar.Name);

        Assert.Equal(new DateTime(2026, 4, 4, 0, 0, 0, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2025, 6, 2, 0, 0, 0, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 6, 2, 0, 0, 0, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Lxcc3SYeXq3VFNLq", response.Registrant.RegistryId);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("active", response.DomainStatus[0]);

        Assert.Equal("signed delegation", response.DnsSecStatus);
        Assert.Equal(15, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_nameservers_with_ip()
    {
        var sample = SampleReader.Read("whois.iis.se", "se", "found", "loopia.se.txt");
        var response = parser.Parse("whois.iis.se", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.iis.se/se/found/01", response.TemplateName);

        Assert.Equal("loopia.se", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Loopia AB", response.Registrar.Name);

        Assert.Equal(new DateTime(2025, 9, 15, 0, 0, 0, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2003, 9, 15, 0, 0, 0, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2026, 9, 15, 0, 0, 0, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("lrc9039-9244", response.Registrant.RegistryId);

        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns2.loopia.se", response.NameServers[0]);
        Assert.Equal("ns1.loopia.se", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("active", response.DomainStatus[0]);

        Assert.Equal("signed delegation", response.DnsSecStatus);
        Assert.Equal(11, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_assigned()
    {
        var sample = SampleReader.Read("whois.iis.se", "se", "not-assigned", "example.se.txt");
        var response = parser.Parse("whois.iis.se", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotAssigned, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.iis.se/se/found/01", response.TemplateName);

        Assert.Equal("example.se", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("CoreRegistry 2", response.Registrar.Name);

        Assert.Equal(new DateTime(2000, 11, 1, 0, 0, 0, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2006, 4, 18, 0, 0, 0, DateTimeKind.Utc), response.Expiration);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("system", response.DomainStatus[0]);

        Assert.Equal("unsigned delegation", response.DnsSecStatus);
        Assert.Equal(9, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.iis.se", "se", "not-found", "u34jedzcq.se.txt");
        var response = parser.Parse("whois.iis.se", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.iis.se/se/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.se", response.DomainName.ToString());


        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_ok()
    {
        var sample = SampleReader.Read("whois.iis.se", "se", "found", "google.se.txt");
        var response = parser.Parse("whois.iis.se", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.iis.se/se/found/01", response.TemplateName);

        Assert.Equal("google.se", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("MarkMonitor Inc", response.Registrar.Name);

        Assert.Equal(new DateTime(2025, 9, 18, 0, 0, 0, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2003, 8, 27, 0, 0, 0, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2026, 10, 20, 0, 0, 0, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("mmr8008-171440", response.Registrant.RegistryId);

        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("active", response.DomainStatus[0]);

        Assert.Equal("unsigned delegation", response.DnsSecStatus);
        Assert.Equal(13, response.FieldsParsed);
    }

    [Fact]
    public void Test_other_status_serverhold()
    {
        var sample = SampleReader.Read("whois.iis.se", "se", "found", "other_status_serverhold.txt");
        var response = parser.Parse("whois.iis.se", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Deactivated, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.iis.se/se/found/01", response.TemplateName);

        Assert.Equal("ogogle.se", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Frobbit AB", response.Registrar.Name);

        Assert.Equal(new DateTime(2012, 02, 20, 00, 00, 00, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2008, 06, 14, 00, 00, 00, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2013, 06, 14, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("magnus4427-00001", response.Registrant.RegistryId);

        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.binero.se", response.NameServers[0]);
        Assert.Equal("ns2.binero.se", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("deactivated", response.DomainStatus[0]);

        Assert.Equal("unsigned delegation", response.DnsSecStatus);
        Assert.Equal(11, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found_status_available()
    {
        var sample = SampleReader.Read("whois.iis.se", "se", "not-found", "not_found_status_available.txt");
        var response = parser.Parse("whois.iis.se", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.iis.se/se/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.se", response.DomainName.ToString());


        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.iis.se", "se", "found", "found_status_registered.txt");
        var response = parser.Parse("whois.iis.se", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.iis.se/se/found/01", response.TemplateName);

        Assert.Equal("google.se", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("MarkMonitor Inc", response.Registrar.Name);

        Assert.Equal(new DateTime(2013, 09, 18, 00, 00, 00, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2008, 10, 20, 00, 00, 00, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2014, 10, 20, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("mmr8008-53808", response.Registrant.RegistryId);

        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("active", response.DomainStatus[0]);

        Assert.Equal("unsigned delegation", response.DnsSecStatus);
        Assert.Equal(13, response.FieldsParsed);
    }
}
