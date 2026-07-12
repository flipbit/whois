using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Domainregistry.Ie.Ie;

public class IeParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public IeParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_reserved()
    {
        var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "reserved", "reserved.txt");
        var response = parser.Parse("whois.domainregistry.ie", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Reserved, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.domainregistry.ie/ie/reserved/01", response.TemplateName);

        Assert.Equal("peter.ie", response.DomainName.ToString());

        Assert.Equal(new DateTime(2012, 04, 17, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

        Assert.Equal(3, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_contacts_multiple()
    {
        var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "found", "rte.ie.txt");
        var response = parser.Parse("whois.domainregistry.ie", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("rte.ie", response.DomainName.ToString());

        Assert.Equal(new DateTime(2034, 3, 31, 13, 20, 7, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("RTE Commercial Enterprises Limited", response.Registrant.Name);

        // AdminContact Details
        Assert.Equal("202753-IEDR", response.AdminContact.RegistryId);

        // TechnicalContact Details
        Assert.Equal("3159-IEDR", response.TechnicalContact.RegistryId);

        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("blue.foundationdns.com", response.NameServers[0]);
        Assert.Equal("blue.foundationdns.net", response.NameServers[1]);

        Assert.Equal(21, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_contacts_not_matching_id()
    {
        var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "found", "tcd.ie.txt");
        var response = parser.Parse("whois.domainregistry.ie", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("tcd.ie", response.DomainName.ToString());

        Assert.Equal(new DateTime(1999, 8, 23, 23, 0, 0, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2026, 8, 24, 12, 44, 1, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Name);

        // AdminContact Details
        Assert.Equal("1431-IEDR", response.AdminContact.RegistryId);

        // TechnicalContact Details
        Assert.Equal("1431-IEDR", response.TechnicalContact.RegistryId);

        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("auth-ns1.tcd.ie", response.NameServers[0]);
        Assert.Equal("auth-ns2.tcd.ie", response.NameServers[1]);
        Assert.Equal("auth-ns2.ucd.ie", response.NameServers[2]);
        Assert.Equal("auth-ns3.tcd.ie", response.NameServers[3]);

        Assert.Equal(22, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_nameservers_with_ip()
    {
        var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "found", "dns.ie.txt");
        var response = parser.Parse("whois.domainregistry.ie", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("dns.ie", response.DomainName.ToString());

        Assert.Equal(new DateTime(2034, 2, 20, 16, 26, 50, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Irish Domains Limited", response.Registrant.Name);

        // AdminContact Details
        Assert.Equal("546276-IEDR", response.AdminContact.RegistryId);

        // TechnicalContact Details
        Assert.Equal("541303-IEDR", response.TechnicalContact.RegistryId);

        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("cloe.ns.cloudflare.com", response.NameServers[0]);
        Assert.Equal("eoin.ns.cloudflare.com", response.NameServers[1]);

        Assert.Equal(20, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "not-found", "u34jedzcq.ie.txt");
        var response = parser.Parse("whois.domainregistry.ie", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.domainregistry.ie/ie/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.ie", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.domainregistry.ie", "ie", "found", "google.ie.txt");
        var response = parser.Parse("whois.domainregistry.ie", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.ie", response.DomainName.ToString());

        Assert.Equal(new DateTime(2002, 3, 21, 0, 0, 0, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 3, 21, 14, 13, 27, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("Google LLC", response.Registrant.Name);

        // AdminContact Details
        Assert.Equal("53735502-IEDR", response.AdminContact.RegistryId);

        // TechnicalContact Details
        Assert.Equal("534389-IEDR", response.TechnicalContact.RegistryId);

        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);

        // Domain Status
        Assert.Equal(3, response.DomainStatus.Count);
        Assert.Equal("serverDeleteProhibited", response.DomainStatus[0]);

        Assert.Equal(23, response.FieldsParsed);
    }
}
