using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Io.Io;

public class IoParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public IoParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.io", "io", "found", "google.io.txt");
        var response = parser.Parse("whois.nic.io", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("google.io", response.DomainName.ToString());

        Assert.Equal(new DateTime(2026, 09, 30, 01, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("REDACTED", response.Registrant.Name);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("REDACTED", response.Registrant.Address[0]);
        Assert.Equal("REDACTED", response.Registrant.Address[1]);
        Assert.Equal("CA", response.Registrant.Address[2]);
        Assert.Equal("REDACTED", response.Registrant.Address[3]);

        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns4.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns2.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(6, response.DomainStatus.Count);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);

        Assert.Equal(47, response.FieldsParsed);
    }

    [Fact]
    public void Test_reserved()
    {
        var sample = SampleReader.Read("whois.nic.io", "io", "reserved", "reserved.txt");
        var response = parser.Parse("whois.nic.io", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Reserved, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.io/io/reserved/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.io", "io", "not-found", "u34jedzcq.io.txt");
        var response = parser.Parse("whois.nic.io", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/03", response.TemplateName);

        Assert.Null(response.DomainName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.nic.io", "io", "found", "redis.io.txt");
        var response = parser.Parse("whois.nic.io", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("redis.io", response.DomainName.ToString());

        Assert.Equal(new DateTime(2027, 05, 28, 22, 09, 44, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("REDACTED", response.Registrant.Name);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("REDACTED", response.Registrant.Address[0]);
        Assert.Equal("REDACTED", response.Registrant.Address[1]);
        Assert.Equal("CO", response.Registrant.Address[2]);
        Assert.Equal("REDACTED", response.Registrant.Address[3]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns-247.awsdns-30.com", response.NameServers[0]);
        Assert.Equal("ns-1248.awsdns-28.org", response.NameServers[1]);
        Assert.Equal("ns-791.awsdns-34.net", response.NameServers[2]);
        Assert.Equal("ns-1731.awsdns-24.co.uk", response.NameServers[3]);

        // Domain Status
        Assert.Equal(2, response.DomainStatus.Count);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[0]);

        Assert.Equal(43, response.FieldsParsed);
    }
}
