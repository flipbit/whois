using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Audns.Net.Au.Au;

public class AuParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public AuParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.audns.net.au", "au", "found", "pinewood.com.au.txt");
        var response = parser.Parse("whois.audns.net.au", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(12, response.FieldsParsed);
        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("pinewood.com.au", response.DomainName.ToString());

        Assert.Null(response.Registrar.Name);

        Assert.Null(response.Updated);
        Assert.Equal("ABN 75143185406", response.Registrant.RegistryId);
        Assert.Null(response.Registrant.Name);

        Assert.Null(response.AdminContact);

        Assert.Null(response.TechnicalContact);


        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("dns1.netfleet.com.au", response.NameServers[0]);
        Assert.Equal("dns2.netfleet.com.au", response.NameServers[1]);

        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("serverRenewProhibited", response.DomainStatus[0]);
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.audns.net.au", "au", "not-found", "not_found.txt");
        var response = parser.Parse("whois.audns.net.au", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(1, response.FieldsParsed);
        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.audns.net.au/au/not-found/01", response.TemplateName);
    }

    [Fact]
    public void Test_found_status_registered()
    {
        var sample = SampleReader.Read("whois.audns.net.au", "au", "found", "google.com.au.txt");
        var response = parser.Parse("whois.audns.net.au", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(18, response.FieldsParsed);
        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/02", response.TemplateName);

        Assert.Equal("google.com.au", response.DomainName.ToString());


        Assert.Null(response.Updated);
        Assert.Null(response.Registrant);

        Assert.Null(response.AdminContact);

        Assert.Null(response.TechnicalContact);


        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns1.google.com", response.NameServers[0]);
        Assert.Equal("ns2.google.com", response.NameServers[1]);
        Assert.Equal("ns3.google.com", response.NameServers[2]);
        Assert.Equal("ns4.google.com", response.NameServers[3]);

        Assert.Equal(6, response.DomainStatus.Count);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
        Assert.Equal("serverDeleteProhibited", response.DomainStatus[1]);
        Assert.Equal("serverRenewProhibited", response.DomainStatus[2]);
        Assert.Equal("serverTransferProhibited", response.DomainStatus[3]);
    }
}
