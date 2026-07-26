using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Centralnic.Com.GrCom;

public class GrComParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public GrComParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.centralnic.com", "gr.com", "not-found", "not_found.txt");
        var response = parser.Parse("whois.centralnic.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.centralnic.com/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.centralnic.com", "gr.com", "found", "found.txt");
        var response = parser.Parse("whois.centralnic.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.centralnic.com/found/01", response.TemplateName);

        Assert.Equal("google.gr.com", response.DomainName.ToString());
        Assert.Equal("CNIC-DO735168", response.RegistryDomainId);

        Assert.Equal(new DateTime(2012, 6, 23, 10, 38, 2, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2011, 2, 7, 13, 10, 14, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2015, 2, 7, 23, 59, 59, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("H1346485", response.Registrant.RegistryId);


        // BillingContact Details
        Assert.Equal("H1346485", response.BillingContact.RegistryId);


        // TechnicalContact Details
        Assert.Equal("H1346485", response.TechnicalContact.RegistryId);


        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("f1g1ns1.dnspod.net", response.NameServers[0]);
        Assert.Equal("f1g1ns2.dnspod.net", response.NameServers[1]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("ok", response.DomainStatus[0]);

        Assert.Equal("Unsigned", response.DnsSecStatus);
        Assert.Equal(13, response.FieldsParsed);
    }
}
