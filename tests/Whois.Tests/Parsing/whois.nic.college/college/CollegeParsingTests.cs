using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.College.College;

public class CollegeParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public CollegeParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.college", "college", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.college", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.college", "college", "found", "nic.college.txt");
        var response = parser.Parse("whois.nic.college", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/02", response.TemplateName);

        Assert.Equal("nic.college", response.DomainName.ToString());
        Assert.Equal("D1465621-CNIC", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("XYZ.com, LLC", response.Registrar.Name);
        Assert.Equal("9999", response.Registrar.IanaId);
        Assert.Equal("https://gen.xyz/", response.Registrar.Url);
        Assert.Equal("whois.nic.xyz", response.Registrar.WhoisServer.Value);

        Assert.Equal(new DateTime(2026, 02, 12, 15, 12, 35, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2013, 09, 11, 11, 58, 15, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2026, 09, 11, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Null(response.Registrant);

        // Registrant Address


        // AdminContact Details
        Assert.Null(response.AdminContact);

        // AdminContact Address


        // BillingContact Details
        Assert.Null(response.BillingContact);

        // BillingContact Address


        // TechnicalContact Details
        Assert.Null(response.TechnicalContact);

        // TechnicalContact Address


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("a.nic.college", response.NameServers[0]);
        Assert.Equal("b.nic.college", response.NameServers[1]);
        Assert.Equal("c.nic.college", response.NameServers[2]);
        Assert.Equal("d.nic.college", response.NameServers[3]);

        // Domain Status
        Assert.Equal(4, response.DomainStatus.Count);
        Assert.Equal("serverRenewProhibited", response.DomainStatus[0]);
        Assert.Equal("serverUpdateProhibited", response.DomainStatus[1]);
        Assert.Equal("serverDeleteProhibited", response.DomainStatus[2]);
        Assert.Equal("serverTransferProhibited", response.DomainStatus[3]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(21, response.FieldsParsed);
    }
}
