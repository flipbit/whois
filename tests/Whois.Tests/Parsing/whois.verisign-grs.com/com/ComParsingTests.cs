using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Verisign.Grs.Com.Com;

public class ComParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public ComParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.verisign-grs.com", "com", "found", "found.txt");
        var response = parser.Parse("whois.verisign-grs.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/02", response.TemplateName);

        Assert.Equal("y.com", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("RESERVED-INTERNET ASSIGNED NUMBERS AUTHORITY", response.Registrar.Name);

        Assert.Equal(new DateTime(2009, 12, 09, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(1993, 12, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2010, 12, 08, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Domain Status
        Assert.Equal(3, response.DomainStatus.Count);
        Assert.Equal("serverDeleteProhibited", response.DomainStatus[0]);
        Assert.Equal("serverTransferProhibited", response.DomainStatus[1]);
        Assert.Equal("serverUpdateProhibited", response.DomainStatus[2]);

        Assert.Equal(9, response.FieldsParsed);
    }

    [Fact]
    public void Test_pending_delete()
    {
        var sample = SampleReader.Read("whois.verisign-grs.com", "com", "pending-delete", "pending_delete.txt");
        var response = parser.Parse("whois.verisign-grs.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.PendingDelete, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/02", response.TemplateName);

        Assert.Equal("killianestates.com", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("GODADDY.COM, LLC", response.Registrar.Name);

        Assert.Equal(new DateTime(2013, 05, 05, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2010, 05, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2013, 05, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns75.domaincontrol.com", response.NameServers[0]);
        Assert.Equal("ns76.domaincontrol.com", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("pendingDelete", response.DomainStatus[0]);

        Assert.Equal(9, response.FieldsParsed);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.verisign-grs.com", "com", "not-found", "not_found.txt");
        var response = parser.Parse("whois.verisign-grs.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/07", response.TemplateName);

        Assert.Equal("u34jedzcq.com", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.verisign-grs.com", "com", "found", "found_status_registered.txt");
        var response = parser.Parse("whois.verisign-grs.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(23, response.FieldsParsed);
        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/02", response.TemplateName);

        Assert.Equal("google.com", response.DomainName.ToString());
        Assert.Equal("2138514_DOMAIN_COM-VRSN", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("MarkMonitor Inc.", response.Registrar.Name);
        Assert.Equal("http://www.markmonitor.com", response.Registrar.Url);
        Assert.Equal("whois.markmonitor.com", response.Registrar.WhoisServer.Value);
        Assert.Equal("abusecomplaints@markmonitor.com", response.Registrar.AbuseEmail);
        Assert.Equal("+1.2083895740", response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2011, 7, 20, 16, 55, 31), response.Updated);
        Assert.Equal(new DateTime(1997, 9, 15, 4, 0, 0), response.Registered);
        Assert.Equal(new DateTime(2020, 9, 14, 4, 0, 0), response.Expiration);

        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        // Domain Status
        Assert.Equal(6, response.DomainStatus.Count);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[1]);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[2]);
        Assert.Equal("serverDeleteProhibited", response.DomainStatus[3]);
        Assert.Equal("serverTransferProhibited", response.DomainStatus[4]);
        Assert.Equal("serverUpdateProhibited", response.DomainStatus[5]);
    }
}
