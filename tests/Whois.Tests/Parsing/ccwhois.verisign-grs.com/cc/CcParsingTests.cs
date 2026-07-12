using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Ccwhois.Verisign.Grs.Com.Cc;

public class CcParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public CcParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("ccwhois.verisign-grs.com", "cc", "found", "found.txt");
        var response = parser.Parse("ccwhois.verisign-grs.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal("m4r0c-s3curity.cc", response.DomainName.ToString());

        Assert.Equal("TUCOWS INC.", response.Registrar.Name);
        Assert.Equal("http://domainhelp.opensrs.net", response.Registrar.Url);
        Assert.Equal("whois.tucows.com", response.Registrar.WhoisServer.Value);

        Assert.Equal(new DateTime(2010, 5, 7, 0, 0, 0), response.Updated);
        Assert.Equal(new DateTime(2009, 3, 26, 0, 0, 0), response.Registered);
        Assert.Equal(new DateTime(2011, 3, 26, 0, 0, 0), response.Expiration);

        Assert.Equal(2, response.DomainStatus.Count);
        Assert.Equal("CLIENT-XFER-PROHIBITED", response.DomainStatus[0]);
        Assert.Equal("CLIENT-UPDATE-PROHIBITED", response.DomainStatus[1]);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("ccwhois.verisign-grs.com", "cc", "not-found", "u34jedzcq.cc.txt");
        var response = parser.Parse("ccwhois.verisign-grs.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);
        Assert.Equal("u34jedzcq.cc", response.DomainName.ToString());
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("ccwhois.verisign-grs.com", "cc", "found", "google.cc.txt");
        var response = parser.Parse("ccwhois.verisign-grs.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal("google.cc", response.DomainName.ToString());
        Assert.Equal("86420657_DOMAIN_CC-VRSN", response.RegistryDomainId);

        Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);
        Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);
        Assert.Equal("whois.markmonitor.com", response.Registrar.WhoisServer.Value);
        Assert.Equal("abusecomplaints@markmonitor.com", response.Registrar.AbuseEmail);
        Assert.Equal("+1.2086851750", response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2026, 5, 6, 10, 52, 12, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1999, 6, 7, 4, 0, 0, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 6, 7, 4, 0, 0, DateTimeKind.Utc), response.Expiration);

        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        Assert.Equal(6, response.DomainStatus.Count);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[1]);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[2]);
        Assert.Equal("serverDeleteProhibited", response.DomainStatus[3]);
        Assert.Equal("serverTransferProhibited", response.DomainStatus[4]);
        Assert.Equal("serverUpdateProhibited", response.DomainStatus[5]);

        Assert.Equal("unsigned", response.DnsSecStatus);
    }
}
