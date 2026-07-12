using Xunit;

namespace Whois;

public class ResourceReaderTests
{
    [Fact]
    public void TestGetNames()
    {
        var names = ResourceReader.GetNames("capetown-whois.registry.net.za", "capetown");

        Assert.Equal(2, names.Count);
        Assert.Equal("Whois.Resources.capetown_whois.registry.net.za.capetown.found.01.txt", names[0]);
        Assert.Equal("Whois.Resources.capetown_whois.registry.net.za.capetown.not_found.01.txt", names[1]);
    }

    [Fact]
    public void TestGetNamesWithDifferentCase()
    {
        var names = ResourceReader.GetNames("Capetown-whois.registry.net.za", "Capetown");

        Assert.Equal(2, names.Count);
        Assert.Equal("Whois.Resources.capetown_whois.registry.net.za.capetown.found.01.txt", names[0]);
        Assert.Equal("Whois.Resources.capetown_whois.registry.net.za.capetown.not_found.01.txt", names[1]);
    }

    [Fact]
    public void TestGetNamesWhenNotFound()
    {
        var names = ResourceReader.GetNames("missing.server", "missing.tld");

        Assert.Empty(names);
    }

    [Fact]
    public void TestGetNamesWhenEmptyInputs()
    {
        var names = ResourceReader.GetNames(string.Empty, string.Empty);

        Assert.Empty(names);
    }

    [Fact]
    public void TestGetNamesWhenNullInputs()
    {
        var names = ResourceReader.GetNames(null, null);

        Assert.Empty(names);
    }

    [Fact]
    public void TestGetContent()
    {
        var content = ResourceReader.GetContent("Whois.Resources.capetown_whois.registry.net.za.capetown.found.01.txt");

        Assert.True(content.Length > 0);
    }

    [Fact]
    public void TestGetContentWhenNotFound()
    {
        var content = ResourceReader.GetContent("missing");

        Assert.True(content.Length == 0);
    }
}
