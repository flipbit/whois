using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Hu.Hu;

public class HuParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public HuParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.nic.hu", "hu", "not-found", "not_found.txt");
        var response = parser.Parse("whois.nic.hu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.hu/hu/not-found/01", response.TemplateName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.nic.hu", "hu", "found", "google.hu.txt");
        var response = parser.Parse("whois.nic.hu", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.nic.hu/hu/found/01", response.TemplateName);

        Assert.Equal("google.hu", response.DomainName.ToString());

        Assert.Null(response.Registered);

        Assert.Equal(2, response.FieldsParsed);
    }
}
