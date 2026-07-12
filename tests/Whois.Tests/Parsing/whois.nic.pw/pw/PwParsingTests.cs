using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Pw.Pw;

public class PwParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public PwParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.pw", "pw", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.pw", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.pw", "pw", "found", "google.pw.txt");
        var response = parser.Parse("whois.nic.pw", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/02", response.TemplateName);

        Assert.Equal("google.pw", response.DomainName.ToString());
        Assert.Equal("D949924-CNIC", response.RegistryDomainId);

        // Registrar Details
        Assert.Equal("292", response.Registrar.IanaId);
        Assert.Equal("+1.2086851750", response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2026, 02, 02, 18, 00, 13, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2012, 10, 12, 10, 19, 46, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2027, 02, 10, 23, 59, 59, 000, DateTimeKind.Utc), response.Expiration);

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
        Assert.Equal(0, response.NameServers.Count);

        // Domain Status
        Assert.Equal(4, response.DomainStatus.Count);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[0]);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[1]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[2]);
        Assert.Equal("inactive", response.DomainStatus[3]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(17, response.FieldsParsed);
    }
}
