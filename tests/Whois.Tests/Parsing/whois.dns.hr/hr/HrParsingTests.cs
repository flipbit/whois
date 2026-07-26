using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dns.Hr.Hr;

public class HrParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public HrParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.dns.hr", "hr", "not-found", "not_found.txt");
        var response = parser.Parse("whois.dns.hr", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.dns.hr/hr/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.dns.hr", "hr", "found", "google.hr.txt");
        var response = parser.Parse("whois.dns.hr", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.dns.hr/hr/found/01", response.TemplateName);

        Assert.Equal("google.hr", response.DomainName.ToString());

        Assert.Equal(new DateTime(2014, 09, 21, 00, 00, 00, DateTimeKind.Utc), response.Expiration);

        // Registrant Details
        Assert.Equal("DD274636-DNSHR", response.Registrant.RegistryId);
        Assert.Equal("Džanan Drobić", response.Registrant.Name);

        // Registrant Address
        Assert.Equal(4, response.Registrant.Address.Count);
        Assert.Equal("Sayber d.o.o.", response.Registrant.Address[0]);
        Assert.Equal("Poljanička 22", response.Registrant.Address[1]);
        Assert.Equal("10110 Zagreb", response.Registrant.Address[2]);
        Assert.Equal("Hrvatska", response.Registrant.Address[3]);

        // TechnicalContact Details
        Assert.Equal("DD274636-DNSHR", response.TechnicalContact.RegistryId);

        Assert.Equal(10, response.FieldsParsed);
    }
}
