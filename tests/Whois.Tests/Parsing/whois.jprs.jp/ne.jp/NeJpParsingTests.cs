using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Jprs.Jp.NeJp;

public class NeJpParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public NeJpParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.jprs.jp", "ne.jp", "found", "found.txt");
        var response = parser.Parse("whois.jprs.jp", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.jprs.jp/found/01", response.TemplateName);

        Assert.Equal("u-tokyo.ac.jp", response.DomainName.ToString());

        Assert.Equal(new DateTime(2011, 04, 01, 01, 35, 47, 000, DateTimeKind.Utc), response.Updated);

        // Registrant Details
        Assert.Equal("University of Tokyo", response.Registrant.Name);


        // AdminContact Details
        Assert.Equal("MN010JP", response.AdminContact.RegistryId);


        // TechnicalContact Details
        Assert.Equal("MN010JP", response.TechnicalContact.RegistryId);


        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("dns1.nc.u-tokyo.ac.jp", response.NameServers[0]);
        Assert.Equal("dns2.nc.u-tokyo.ac.jp", response.NameServers[1]);
        Assert.Equal("dns3.nc.u-tokyo.ac.jp", response.NameServers[2]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Connected", response.DomainStatus[0]);

        Assert.Equal(10, response.FieldsParsed);
    }

    [Fact]
    public void Test_reserved()
    {
        var sample = SampleReader.Read("whois.jprs.jp", "ne.jp", "reserved", "reserved.txt");
        var response = parser.Parse("whois.jprs.jp", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Reserved, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.jprs.jp/found/01", response.TemplateName);

        Assert.Equal("ne.jp", response.DomainName.ToString());

        Assert.Equal(new DateTime(2005, 03, 30, 17, 37, 52, 000, DateTimeKind.Utc), response.Updated);

        // Nameservers
        Assert.Equal(7, response.NameServers.Count);
        Assert.Equal("a.dns.jp", response.NameServers[0]);
        Assert.Equal("b.dns.jp", response.NameServers[1]);
        Assert.Equal("c.dns.jp", response.NameServers[2]);
        Assert.Equal("d.dns.jp", response.NameServers[3]);
        Assert.Equal("e.dns.jp", response.NameServers[4]);
        Assert.Equal("f.dns.jp", response.NameServers[5]);
        Assert.Equal("g.dns.jp", response.NameServers[6]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Reserved", response.DomainStatus[0]);

        Assert.Equal(11, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.jprs.jp", "ne.jp", "not-found", "not_found.txt");
        var response = parser.Parse("whois.jprs.jp", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.jprs.jp/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.jprs.jp", "ne.jp", "found", "found_status_registered.txt");
        var response = parser.Parse("whois.jprs.jp", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.jprs.jp/found/01", response.TemplateName);

        Assert.Equal("google.ne.jp", response.DomainName.ToString());

        Assert.Equal(new DateTime(2009, 10, 23, 19, 22, 08, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2003, 09, 11, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

        // AdminContact Details
        Assert.Equal("HR058JP", response.AdminContact.RegistryId);

        // TechnicalContact Details
        Assert.Equal("TW38378JP", response.TechnicalContact.RegistryId);

        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Connected", response.DomainStatus[0]);

        Assert.Equal(11, response.FieldsParsed);
    }

    [Fact]
    public void Test_reserved_status_reserved()
    {
        var sample = SampleReader.Read("whois.jprs.jp", "ne.jp", "reserved", "reserved_status_reserved.txt");
        var response = parser.Parse("whois.jprs.jp", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Reserved, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.jprs.jp/found/01", response.TemplateName);

        Assert.Equal("ne.jp", response.DomainName.ToString());

        Assert.Equal(new DateTime(2005, 03, 30, 17, 37, 52, 000, DateTimeKind.Utc), response.Updated);

        // Nameservers
        Assert.Equal(7, response.NameServers.Count);
        Assert.Equal("a.dns.jp", response.NameServers[0]);
        Assert.Equal("b.dns.jp", response.NameServers[1]);
        Assert.Equal("c.dns.jp", response.NameServers[2]);
        Assert.Equal("d.dns.jp", response.NameServers[3]);
        Assert.Equal("e.dns.jp", response.NameServers[4]);
        Assert.Equal("f.dns.jp", response.NameServers[5]);
        Assert.Equal("g.dns.jp", response.NameServers[6]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("Reserved", response.DomainStatus[0]);

        Assert.Equal(11, response.FieldsParsed);
    }
}
