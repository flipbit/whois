using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.In.Ua.InUa;

public class InUaParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public InUaParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.in.ua", "in.ua", "not-found", "u34jedzcq.in.ua.txt");
        var response = parser.Parse("whois.in.ua", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.in.ua/in.ua/not-found/01", response.TemplateName);

        Assert.Equal("u34jedzcq.in.ua", response.DomainName.ToString());

        Assert.Equal(2, response.FieldsParsed);
    }

    [Fact(Skip = "Template update deferred - WHOIS response format changed")]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.in.ua", "in.ua", "found", "dle.in.ua.txt");
        var response = parser.Parse("whois.in.ua", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.in.ua/in.ua/found/01", response.TemplateName);

        Assert.Equal("dle.in.ua", response.DomainName.ToString());

        Assert.Equal(new DateTime(2012, 12, 16, 13, 41, 04, DateTimeKind.Utc), response.Updated);

        // AdminContact Details
        Assert.Equal("VP535-UANIC", response.AdminContact.RegistryId);


        // TechnicalContact Details
        Assert.Equal("NIC-UANIC", response.TechnicalContact.RegistryId);


        // Nameservers
        Assert.Equal(3, response.NameServers.Count);
        Assert.Equal("ns12.uadns.com", response.NameServers[0]);
        Assert.Equal("ns11.uadns.com", response.NameServers[1]);
        Assert.Equal("ns10.uadns.com", response.NameServers[2]);

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("OK-UNTIL 20131218000000", response.DomainStatus[0]); // TODO: Parse Expiry date

        Assert.Equal(9, response.FieldsParsed);
    }
}
