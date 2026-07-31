using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Srs.Net.Nz.Nz;

public class NzParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public NzParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_other_status_pendingrelease()
    {
        var sample = SampleReader.Read("whois.srs.net.nz", "nz", "found", "zumbafitness.co.nz.txt");
        var response = parser.Parse("whois.srs.net.nz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/02", response.TemplateName);

        Assert.Equal("zumbafitness.co.nz", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("MarkMonitor. Inc", response.Registrar.Name);
        Assert.Null(response.Registrar.AbuseEmail);
        Assert.Null(response.Registrar.AbuseTelephoneNumber);


        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("abby.ns.cloudflare.com", response.NameServers[0]);
        Assert.Equal("paul.ns.cloudflare.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(2, response.DomainStatus.Count);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(11, response.FieldsParsed);
    }

    [Fact]
    public void Test_throttled()
    {
        var sample = SampleReader.Read("whois.srs.net.nz", "nz", "throttled", "throttled.txt");
        var response = parser.Parse("whois.srs.net.nz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Throttled, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.srs.net.nz/nz/found/01", response.TemplateName);

        Assert.Equal("jaycar.co.nz", response.DomainName.ToString());

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("440 Request Denied", response.DomainStatus[0]);

        Assert.Equal(3, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.srs.net.nz", "nz", "not-found", "u34jedzcq.co.nz.txt");
        var response = parser.Parse("whois.srs.net.nz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.srs.net.nz/nz/found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.co.nz", response.DomainName.ToString());

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("220 Available", response.DomainStatus[0]);

        Assert.Equal(3, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_invalid()
    {
        var sample = SampleReader.Read("whois.srs.net.nz", "nz", "invalid", "u34jedzcq.nz.txt");
        var response = parser.Parse("whois.srs.net.nz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Invalid, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.srs.net.nz/nz/found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.nz", response.DomainName.ToString());

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("500 Invalid characters in query string", response.DomainStatus[0]);

        Assert.Equal(3, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.srs.net.nz", "nz", "found", "google.co.nz.txt");
        var response = parser.Parse("whois.srs.net.nz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/02", response.TemplateName);

        Assert.Equal("google.co.nz", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("MarkMonitor. Inc", response.Registrar.Name);
        Assert.Null(response.Registrar.AbuseEmail);
        Assert.Null(response.Registrar.AbuseTelephoneNumber);


        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


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
        Assert.Equal(3, response.DomainStatus.Count);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(14, response.FieldsParsed);
    }
}
