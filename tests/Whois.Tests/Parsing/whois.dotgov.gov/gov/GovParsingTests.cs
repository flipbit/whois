using Xunit;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dotgov.Gov.Gov;

public class GovParsingTests : ParsingTests
{
    private readonly WhoisParser parser;

    public GovParsingTests()
    {

        parser = new WhoisParser();
    }

    [Fact]
    public void Test_not_found()
    {
        var sample = SampleReader.Read("whois.dotgov.gov", "gov", "not-found", "u34jedzcq.gov.txt");
        var response = parser.Parse("whois.dotgov.gov", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.NotFound, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("generic/tld/not-found/03", response.TemplateName);

        Assert.Null(response.DomainName);

        Assert.Equal(1, response.FieldsParsed);
    }

    [Fact]
    public void Test_found()
    {
        var sample = SampleReader.Read("whois.dotgov.gov", "gov", "found", "gsa.gov.txt");
        var response = parser.Parse("whois.dotgov.gov", sample);

        Assert.True(sample.Length > 0);
        Assert.Equal(WhoisStatus.Found, response.Status);

        Assert.Equal(0, response.ParsingErrors);
        Assert.Equal("whois.dotgov.gov/gov/found/01", response.TemplateName);

        Assert.Equal("gsa.gov", response.DomainName.ToString());

        // Domain Status
        Assert.Equal(1, response.DomainStatus.Count);
        Assert.Equal("serverTransferProhibited https://icann.org/epp#serverTransferProhibited", response.DomainStatus[0]);

        Assert.Equal(3, response.FieldsParsed);
    }
}
