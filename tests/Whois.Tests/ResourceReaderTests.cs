using Xunit;

namespace Whois;

public class ResourceReaderTests
{
    private readonly ResourceReader reader;

    public ResourceReaderTests()
    {
        reader = new ResourceReader();
    }

    [Fact]
    public void TestGetNames()
    {
        var names = reader.GetNames("capetown-whois.registry.net.za", "capetown");

        Assert.Equal(2, names.Count);
        Assert.Equal("Whois.Resources.capetown_whois.registry.net.za.capetown.found.01.txt", names[0]);
        Assert.Equal("Whois.Resources.capetown_whois.registry.net.za.capetown.not_found.01.txt", names[1]);
    }

    [Fact]
    public void TestGetNamesWithDifferentCase()
    {
        var names = reader.GetNames("Capetown-whois.registry.net.za", "Capetown");

        Assert.Equal(2, names.Count);
        Assert.Equal("Whois.Resources.capetown_whois.registry.net.za.capetown.found.01.txt", names[0]);
        Assert.Equal("Whois.Resources.capetown_whois.registry.net.za.capetown.not_found.01.txt", names[1]);
    }

    [Fact]
    public void TestGetNamesWhenNotFound()
    {
        var names = reader.GetNames("missing.server", "missing.tld");

        Assert.Empty(names);
    }

    [Fact]
    public void TestGetNamesWhenEmptyInputs()
    {
        var names = reader.GetNames(string.Empty, string.Empty);

        Assert.Empty(names);
    }

    [Fact]
    public void TestGetNamesWhenNullInputs()
    {
        var names = reader.GetNames(null, null);

        Assert.Empty(names);
    }

    [Fact]
    public void TestGetContent()
    {
        var content = reader.GetContent("Whois.Resources.capetown_whois.registry.net.za.capetown.found.01.txt");

        Assert.True(content.Length > 0);
    }

    [Fact]
    public void TestGetContentWhenNotFound()
    {
        var content = reader.GetContent("missing");

        Assert.True(content.Length == 0);
    }
}
