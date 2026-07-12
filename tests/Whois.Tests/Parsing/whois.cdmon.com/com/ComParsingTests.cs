using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Cdmon.Com.Com;

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
        var sample = SampleReader.Read("whois.cdmon.com", "com", "found", "cdmon.com.txt");
        var response = parser.Parse("whois.cdmon.com", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/found/01", response.TemplateName);

        Assert.Equal("cdmon.com", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("10DENCEHISPAHARD, S.L", response.Registrar.Name);
        Assert.Equal("1403", response.Registrar.IanaId);
        Assert.Equal("https://www.cdmon.com", response.Registrar.Url);
        Assert.Equal("whois.cdmon.com", response.Registrar.WhoisServer.Value);
        Assert.Equal("abuse@cdmon.com", response.Registrar.AbuseEmail);
        Assert.Equal("+34.935677577", response.Registrar.AbuseTelephoneNumber);

        Assert.Equal(new DateTime(2018, 10, 25, 12, 11, 22, 000, DateTimeKind.Utc), response.Updated);
        Assert.Equal(new DateTime(2001, 08, 12, 15, 02, 57, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2034, 08, 12, 15, 02, 53, 000, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Name);
        Assert.Equal("10dencehispahard,s.l.", response.Registrant.Organization);
        Assert.Null(response.Registrant.TelephoneNumber);
        Assert.Null(response.Registrant.Email);

        // Registrant Address
        Assert.Equal(5, response.Registrant.Address.Count);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Address[0]);
        Assert.Equal("REDACTED FOR PRIVACY", response.Registrant.Address[1]);
        Assert.Equal("Barcelona", response.Registrant.Address[2]);
        Assert.Equal("ES", response.Registrant.Address[3]);


        // AdminContact Details
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Name);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Organization);
        Assert.Null(response.AdminContact.TelephoneNumber);
        Assert.Null(response.AdminContact.Email);

        // AdminContact Address
        Assert.Equal(5, response.AdminContact.Address.Count);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Address[0]);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Address[1]);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Address[2]);
        Assert.Equal("REDACTED FOR PRIVACY", response.AdminContact.Address[3]);


        // TechnicalContact Details
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Name);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Organization);
        Assert.Null(response.TechnicalContact.TelephoneNumber);
        Assert.Null(response.TechnicalContact.Email);

        // TechnicalContact Address
        Assert.Equal(5, response.TechnicalContact.Address.Count);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[0]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[1]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[2]);
        Assert.Equal("REDACTED FOR PRIVACY", response.TechnicalContact.Address[3]);


        // Nameservers
        Assert.Equal(4, response.NameServers.Count);
        Assert.Equal("ns-1123.cdmon.com", response.NameServers[0]);
        Assert.Equal("ns-1740.cdmon.com", response.NameServers[1]);
        Assert.Equal("ns-61.cdmon.com", response.NameServers[2]);

        // Domain Status
        Assert.Equal(3, response.DomainStatus.Count);
        Assert.Equal("clientUpdateProhibited", response.DomainStatus[0]);
        Assert.Equal("clientDeleteProhibited", response.DomainStatus[1]);
        Assert.Equal("clientTransferProhibited", response.DomainStatus[2]);

        Assert.Equal("unsigned", response.DnsSecStatus);
        Assert.Equal(44, response.FieldsParsed);
    }
}
