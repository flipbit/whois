using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Domain.Registry.Nl.Nl;

public class NlParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public NlParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "found", "tntpost.nl.txt");
        var response = parser.Parse("whois.domain-registry.nl", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.domain-registry.nl/nl/found/02", response.TemplateName);

        Assert.Equal("tntpost.nl", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Transip BV", response.Registrar.Name);

        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.tntpost.nl", response.NameServers[0]);
        Assert.Equal("ns2.tntpost.nl", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("active", response.DomainStatus[0]);

        Assert.Equal(6, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_assigned()
    {
        var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "not-assigned", "smsexdates.nl.txt");
        var response = parser.Parse("whois.domain-registry.nl", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotAssigned, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.domain-registry.nl/nl/found/02", response.TemplateName);

        Assert.Equal("smsexdates.nl", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("JK Websolutions", response.Registrar.Name);

        // Nameservers
        Assert.Equal(1, response.NameServers.Count);
        Assert.Equal("ns1.jkwebsolutions.nl", response.NameServers[0]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("inactive", response.DomainStatus[0]);

        Assert.Equal("no", response.DnsSecStatus);
        Assert.Equal(6, response.FieldsParsed);
    }

    [Fact]
    public void Test_throttled()
    {
        var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "throttled", "throttled.txt");
        var response = parser.Parse("whois.domain-registry.nl", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Throttled, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.domain-registry.nl/nl/throttled/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_throttled_response_throttled_daily()
    {
        var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "throttled", "throttled_response_throttled_daily.txt");
        var response = parser.Parse("whois.domain-registry.nl", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Throttled, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.domain-registry.nl/nl/throttled/02", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_unavailable()
    {
        var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "unavailable", "unavailable.txt");
        var response = parser.Parse("whois.domain-registry.nl", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Unavailable, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.domain-registry.nl/nl/unavailable/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "not-found", "u34jedzcq.nl.txt");
        var response = parser.Parse("whois.domain-registry.nl", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.domain-registry.nl/nl/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.nl", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_quarantined()
    {
        var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "redemption", "martijn-webdesign.nl.txt");
        var response = parser.Parse("whois.domain-registry.nl", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Quarantined, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.domain-registry.nl/nl/found/02", response.TemplateName);

        Assert.Equal("martijn-webdesign.nl", response.DomainName.ToString());


        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("in quarantine", response.DomainStatus[0]);

        Assert.Equal(3, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.domain-registry.nl", "nl", "found", "google.nl.txt");
        var response = parser.Parse("whois.domain-registry.nl", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.domain-registry.nl/nl/found/01", response.TemplateName);

        Assert.Equal("google.nl", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("MarkMonitor International LTD", response.Registrar.Name);

        Assert.Equal(new DateTime(2009, 02, 11, 00, 00, 00, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1999, 05, 27, 00, 00, 00, DateTimeKind.Utc), response.Registered);

        // Registrant Details
        Assert.Equal("GOO001748-MARKM", response.Registrant.RegistryId);
        Assert.Equal("Google Inc.", response.Registrant.Name);

        // Registrant Address
        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("Amphitheatre Parkway 1600", response.Registrant.Address[0]);
        Assert.Equal("94043", response.Registrant.Address[1]);
        Assert.Equal("MOUNTAIN VIEW CA", response.Registrant.Address[2]);
        Assert.Equal("United States of America", response.Registrant.Address[3]);


        // AdminContact Details
        Assert.Equal("GOO007083-MARKM", response.AdminContact.RegistryId);
        Assert.Equal("GI Google Inc.", response.AdminContact.Name);
        Assert.Equal("+1 (0)6502530000", response.AdminContact.TelephoneNumber);
        Assert.Equal("ccops@markmonitor.com", response.AdminContact.Email);


        // TechnicalContact Details
        Assert.Equal("JOH004771-MARKM", response.TechnicalContact.RegistryId);
        Assert.Equal("M Serlin", response.TechnicalContact.Name);
        Assert.Equal("+1 (0)2083895740", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("ccops@markmonitor.com", response.TechnicalContact.Email);

        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("active", response.DomainStatus[0]);

        Assert.Equal(24, response.FieldsParsed);
    }
}
