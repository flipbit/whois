using Xunit;

namespace Whois.Parsers;

public class WhoisParserTests
{
    private readonly WhoisParser parser;
    private readonly SampleReader sampleReader;

    public WhoisParserTests()
    {
        parser = new WhoisParser();
        sampleReader = new SampleReader();
    }

    [Fact]
    public void TestParseDomainNameWhois()
    {
        var sample = sampleReader.Read("capetown-whois.registry.net.za", "capetown", "found", "registry.capetown.txt");

        var result = parser.Parse("capetown-whois.registry.net.za", sample);

        Assert.NotNull(result);
        Assert.Equal("registry.capetown", result.DomainName.ToString());
        Assert.Equal(WhoisStatus.Found, result.Status);
        Assert.Equal(2, parser.Templates.Count);
    }

    [Fact]
    public void TestParseDomainNameWhoisDoesNotRegisterTemplateTwice()
    {
        var sample = sampleReader.Read("capetown-whois.registry.net.za", "capetown", "found", "registry.capetown.txt");

        parser.Parse("capetown-whois.registry.net.za", sample);
        parser.Parse("capetown-whois.registry.net.za", sample);

        Assert.Equal(2, parser.Templates.Count);
    }
}
