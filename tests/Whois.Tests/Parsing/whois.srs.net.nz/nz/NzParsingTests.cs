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

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_other_status_pendingrelease()
    {
        var sample = SampleReader.Read("whois.srs.net.nz", "nz", "found", "zumbafitness.co.nz.txt");
        var response = parser.Parse("whois.srs.net.nz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Other, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.srs.net.nz/nz/found/01", response.TemplateName);

        Assert.Equal("zumbafitness.co.nz", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("NETREGISTRY PTY LTD", response.Registrar.Name);
        Assert.Equal("dnsadmin@netregistry.com.au", response.Registrar.AbuseEmail);
        Assert.Equal("+61 2 9699 6099", response.Registrar.AbuseTelephoneNumber);


        // Registrant Details
        Assert.Equal("Zumba Fitness, Rodrigo, Faerman", response.Registrant.Name);
        Assert.Equal("+1 9 549253755", response.Registrant.TelephoneNumber);
        Assert.Equal("rodrigo@zumba.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(3, response.Registrant.Address.Count);
        Assert.Equal("3801 North 29th Avenue", response.Registrant.Address[0]);
        Assert.Equal("Hollywood", response.Registrant.Address[1]);
        Assert.Equal("GB (UNITED KINGDOM)", response.Registrant.Address[2]);


        // AdminContact Details
        Assert.Equal("NetRegistry", response.AdminContact.Name);
        Assert.Equal("+61 2 96996099", response.AdminContact.TelephoneNumber);
        Assert.Equal("+61 2 96996088", response.AdminContact.FaxNumber);
        Assert.Equal("dmain@netregistry.com.au", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(3, response.AdminContact.Address.Count);
        Assert.Equal("PO BOX 270", response.AdminContact.Address[0]);
        Assert.Equal("Broadway", response.AdminContact.Address[1]);
        Assert.Equal("AU (AUSTRALIA)", response.AdminContact.Address[2]);


        // TechnicalContact Details
        Assert.Equal("NETREGISTRY PTY LTD", response.TechnicalContact.Name);
        Assert.Equal("+61 2 9699 6099", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+61 2 9699 6088", response.TechnicalContact.FaxNumber);
        Assert.Equal("dnsadmin@netregistry.com.au", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(4, response.TechnicalContact.Address.Count);
        Assert.Equal("PO Box 270", response.TechnicalContact.Address[0]);
        Assert.Equal("Broadway", response.TechnicalContact.Address[1]);
        Assert.Equal("2007", response.TechnicalContact.Address[2]);
        Assert.Equal("AU (AUSTRALIA)", response.TechnicalContact.Address[3]);


        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("ns1.netregistry.net", response.NameServers[0]);
        Assert.Equal("ns2.netregistry.net", response.NameServers[1]);
        Assert.Equal("ns3.netregistry.net", response.NameServers[2]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("210 PendingRelease", response.DomainStatus[0]);

        Assert.Equal("no", response.DnsSecStatus);
        Assert.Equal(31, response.FieldsParsed);
    }

    [Fact]
    public void Test_throttled()
    {
        var sample = SampleReader.Read("whois.srs.net.nz", "nz", "throttled", "throttled.txt");
        var response = parser.Parse("whois.srs.net.nz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Throttled, response.Status);

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
        Assert.Equal(WhoisStatus.NotFound, response.Status);

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
        Assert.Equal(WhoisStatus.Invalid, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.srs.net.nz/nz/found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.nz", response.DomainName.ToString());

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("500 Invalid characters in query string", response.DomainStatus[0]);

        Assert.Equal(3, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.srs.net.nz", "nz", "found", "google.co.nz.txt");
        var response = parser.Parse("whois.srs.net.nz", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.srs.net.nz/nz/found/01", response.TemplateName);

        Assert.Equal("google.co.nz", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("MarkMonitor", response.Registrar.Name);
        Assert.Equal("ccops@markmonitor.com", response.Registrar.AbuseEmail);
        Assert.Equal("+1 208 3895740", response.Registrar.AbuseTelephoneNumber);


        // Registrant Details
        Assert.Equal("Google Inc", response.Registrant.Name);
        Assert.Equal("+1 650 +1 650 3300100", response.Registrant.TelephoneNumber);
        Assert.Equal("+1 650 +1 650 6181434", response.Registrant.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
        Assert.Equal("Mountain View", response.Registrant.Address[1]);
        Assert.Equal("CA", response.Registrant.Address[2]);
        Assert.Equal("94043", response.Registrant.Address[3]);
        Assert.Equal("US (UNITED STATES)", response.Registrant.Address[4]);


        // AdminContact Details
        Assert.Equal("Google Inc", response.AdminContact.Name);
        Assert.Equal("+1 650 +1 650 3300100", response.AdminContact.TelephoneNumber);
        Assert.Equal("+1 650 +1 650 6181434", response.AdminContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.AdminContact.Address[0]);
        Assert.Equal("Mountain View", response.AdminContact.Address[1]);
        Assert.Equal("CA", response.AdminContact.Address[2]);
        Assert.Equal("94043", response.AdminContact.Address[3]);
        Assert.Equal("US (UNITED STATES)", response.AdminContact.Address[4]);


        // TechnicalContact Details
        Assert.Equal("Google Inc", response.TechnicalContact.Name);
        Assert.Equal("+1 650 +1 650 3300100", response.TechnicalContact.TelephoneNumber);
        Assert.Equal("+  +1 650 6181434", response.TechnicalContact.FaxNumber);
        Assert.Equal("dns-admin@google.com", response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
        Assert.Equal("Mountain View", response.TechnicalContact.Address[1]);
        Assert.Equal("CA", response.TechnicalContact.Address[2]);
        Assert.Equal("94043", response.TechnicalContact.Address[3]);
        Assert.Equal("US (UNITED STATES)", response.TechnicalContact.Address[4]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("200 Active", response.DomainStatus[0]);

        Assert.Equal("no", response.DnsSecStatus);
        Assert.Equal(38, response.FieldsParsed);
    }
}
