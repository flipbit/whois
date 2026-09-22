using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Sn.Sn;

public class SnParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public SnParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.sn", "sn", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.sn", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.NotFound, response.Status);

    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.sn", "sn", "found", "google.sn.txt");
        var response = parser.Parse("whois.nic.sn", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(RegistrationStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.sn/sn/found/02", response.TemplateName);

        Assert.Equal("google.sn", response.DomainName.ToString());

        // Registrar Details
        Assert.Equal("MARKMONITOR Inc.", response.Registrar.Name);

        Assert.Null(response.Registered);
    }
}
