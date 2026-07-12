using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dns.Be.Be;

public class BeParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public BeParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.dns.be", "be", "found", "register.be.txt");
        var response = parser.Parse("whois.dns.be", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.dns.be/be/found/01", response.TemplateName);

        Assert.Equal("register.be", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("Register NV/SA", response.Registrar.Name);
        Assert.Equal("www.register.be", response.Registrar.Url);

        Assert.Equal(new DateTime(2000, 12, 12, 0, 0, 0), response.Registered);

        // TechnicalContact Details
        Assert.Equal("Register.be Technical Support", response.TechnicalContact.Name);
        Assert.Equal("Register.be", response.TechnicalContact.Organization);
        Assert.Equal("+32.22473720", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+32.22473701", response.TechnicalContact.FaxNumber);
        Assert.Equal("info@register.be", response.TechnicalContact.Email);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("NOT AVAILABLE", response.DomainStatus[0]);

        Assert.Equal(11, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.dns.be", "be", "not-found", "u34jedzcq.be.txt");
        var response = parser.Parse("whois.dns.be", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.dns.be/be/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.be", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_error()
    {
        var sample = SampleReader.Read("whois.dns.be", "be", "error", "www.kimdemolenaer.be.txt");
        var response = parser.Parse("whois.dns.be", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Error, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.dns.be/be/error/01", response.TemplateName);

        Assert.Equal("www.kimdemolenaer.be", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_available()
    {
        var sample = SampleReader.Read("whois.dns.be", "be", "not-available", "not_available.txt");
        var response = parser.Parse("whois.dns.be", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.dns.be/be/found/01", response.TemplateName);

        Assert.Equal("gratisdatingplaza.be", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("AXC", response.Registrar.Name);
        Assert.Equal("axc.nl/", response.Registrar.Url);

        Assert.Equal(new DateTime(2011, 2, 15, 0, 0, 0), response.Registered);

        // TechnicalContact Details
        Assert.Equal("R. Bashir", response.TechnicalContact.Name);
        Assert.Equal("AXC", response.TechnicalContact.Organization);
        Assert.Equal("+31.787112586", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+31.787112587", response.TechnicalContact.FaxNumber);
        Assert.Equal("support@axc.nl", response.TechnicalContact.Email);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns2594.hostgator.com", response.NameServers[0]);
        Assert.Equal("ns2593.hostgator.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("NOT AVAILABLE", response.DomainStatus[0]);

        Assert.Equal(13, response.FieldsParsed);
    }

    [Fact]
    public void Test_out_of_service()
    {
        var sample = SampleReader.Read("whois.dns.be", "be", "out-of-service", "out_of_service.txt");
        var response = parser.Parse("whois.dns.be", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.OutOfService, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.dns.be/be/out-of-service/01", response.TemplateName);

        Assert.Equal("ee", response.DomainName.ToString());

        Assert.Equal(new DateTime(2000, 12, 14, 0, 0, 0), response.Registered);

        // Registrar
        Assert.Equal("www.dns.be", response.Registrar.Url);

        // TechnicalContact Details
        Assert.Equal("DNS BE Tech", response.TechnicalContact.Name);
        Assert.Equal("DNS BE vzw", response.TechnicalContact.Organization);

        // TechnicalContact Address
        Assert.Equal(4, response.TechnicalContact.Address.Count);
        Assert.Equal("Ubicenter", response.TechnicalContact.Address[0]);
        Assert.Equal("Philipssite 5 bus 13", response.TechnicalContact.Address[1]);
        Assert.Equal("300 Leuven", response.TechnicalContact.Address[2]);
        Assert.Equal("BE", response.TechnicalContact.Address[3]);

        Assert.Equal("+32.16284970", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+32.16284971", response.TechnicalContact.FaxNumber);
        Assert.Equal("tech@dns.be", response.TechnicalContact.Email);


        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("OUT OF SERVICE", response.DomainStatus[0]);

        Assert.Equal(14, response.FieldsParsed);
    }

    [Fact]
    public void Test_quarantined()
    {
        var sample = SampleReader.Read("whois.dns.be", "be", "quarantined", "quarantined.txt");
        var response = parser.Parse("whois.dns.be", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Quarantined, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.dns.be/be/quarantined/01", response.TemplateName);

        Assert.Equal("9i", response.DomainName.ToString());

        Assert.Equal(new DateTime(2003, 12, 22, 0, 0, 0), response.Registered);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("QUARANTINE", response.DomainStatus[0]);

        Assert.Equal(4, response.FieldsParsed);
    }

    [Fact]
    public void Test_blocked()
    {
        var sample = SampleReader.Read("whois.dns.be", "be", "blocked", "blocked.txt");
        var response = parser.Parse("whois.dns.be", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Blocked, response.Status);
    }

    [Fact]
    public void Test_throttled()
    {
        var sample = SampleReader.Read("whois.dns.be", "be", "throttled", "throttled.txt");
        var response = parser.Parse("whois.dns.be", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Throttled, response.Status);
    }

    [Fact]
    public void Test_throttled_response_throttled_limit()
    {
        var sample = SampleReader.Read("whois.dns.be", "be", "throttled", "throttled_response_throttled_limit.txt");
        var response = parser.Parse("whois.dns.be", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Throttled, response.Status);
    }

    [Fact]
    public void Test_not_found_status_available()
    {
        var sample = SampleReader.Read("whois.dns.be", "be", "not-found", "not_found_status_available.txt");
        var response = parser.Parse("whois.dns.be", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.dns.be/be/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.be", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_invalid()
    {
        var sample = SampleReader.Read("whois.dns.be", "be", "invalid", "invalid.txt");
        var response = parser.Parse("whois.dns.be", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Error, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.dns.be/be/error/01", response.TemplateName);

        Assert.Equal("www-invalid.kimdemolenaer.be", response.DomainName.ToString());


        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.dns.be", "be", "found", "found_status_registered.txt");
        var response = parser.Parse("whois.dns.be", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);
    }

    [Fact]
    public void Test_youtube()
    {
        var sample = SampleReader.Read("whois.dns.be", "be", "found", "youtu.be.txt");
        var response = parser.Parse("whois.dns.be", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.dns.be/be/found/01", response.TemplateName);

        Assert.Equal("youtu.be", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);
        Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);

        Assert.Equal(new DateTime(2007, 12, 24, 0, 0, 0), response.Registered);

        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns4.google.com", response.NameServers[0]);
        Assert.Equal("ns3.google.com", response.NameServers[1]);
        Assert.Equal("ns1.google.com", response.NameServers[2]);
        Assert.Equal("ns2.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("NOT AVAILABLE", response.DomainStatus[0]);

        Assert.Equal(10, response.FieldsParsed);
    }
}
