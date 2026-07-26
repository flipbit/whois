using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Tcinet.Ru.XnP1ai;

public class XnP1aiParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public XnP1aiParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.tcinet.ru", "xn--p1ai", "not-found", "not_found.txt");
        var response = parser.Parse("whois.tcinet.ru", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.tcinet.ru/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.tcinet.ru", "xn--p1ai", "found", "found.txt");
        var response = parser.Parse("whois.tcinet.ru", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.tcinet.ru/found/01", response.TemplateName);

        Assert.Equal("xn----8sbc3ahklcs4adf.xn--p1ai", response.DomainName.ToString());
        Assert.Equal("форум-кубани.рф", response.DomainName.ToUnicodeString());

        // Registrar Details
        Assert.Equal("REGRU-RF", response.Registrar.Name);

        Assert.Equal(new DateTime(2017, 12, 20, 17, 02, 51, 000, DateTimeKind.Utc), response.Registered);
        Assert.Equal(new DateTime(2020, 12, 20, 17, 02, 51, 000, DateTimeKind.Utc), response.Expiration);

        // Nameservers
        Assert.Equal(2, response.NameServers.Count);
        Assert.Equal("ns1.reg.ru.", response.NameServers[0]);
        Assert.Equal("ns2.reg.ru.", response.NameServers[1]);

        // Domain Status
        Assert.Equal(3, response.DomainStatus.Count);
        Assert.Equal("REGISTERED", response.DomainStatus[0]);
        Assert.Equal("DELEGATED", response.DomainStatus[1]);
        Assert.Equal("UNVERIFIED", response.DomainStatus[2]);

        Assert.Equal(8, response.FieldsParsed);
    }
}
