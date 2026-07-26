using Xunit;

namespace Whois.Servers;

public class BootstrapRegistryTests
{
    [Fact]
    public async Task GetRdapBaseUrl_KnownTld_ReturnsUrl()
    {
        var registry = CreateRegistry();

        var url = await registry.GetRdapBaseUrl("com", CancellationToken.None);

        Assert.NotNull(url);
        Assert.StartsWith("https://", url, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetRdapBaseUrl_UnknownTld_ReturnsNull()
    {
        var registry = CreateRegistry();

        var url = await registry.GetRdapBaseUrl("zzz-nonexistent", CancellationToken.None);

        Assert.Null(url);
    }

    [Fact]
    public async Task GetRdapBaseUrl_CaseInsensitive_ReturnsUrl()
    {
        var registry = CreateRegistry();

        var urlLower = await registry.GetRdapBaseUrl("com", CancellationToken.None);
        var urlUpper = await registry.GetRdapBaseUrl("COM", CancellationToken.None);

        Assert.Equal(urlLower, urlUpper);
    }

    [Fact]
    public async Task GetWhoisServer_KnownTld_ReturnsHostname()
    {
        var registry = CreateRegistry();

        var server = await registry.GetWhoisServer("com", CancellationToken.None);

        Assert.NotNull(server);
        Assert.Contains("whois", server, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetWhoisServer_UnknownTld_ReturnsNull()
    {
        var registry = CreateRegistry();

        var server = await registry.GetWhoisServer("zzz-nonexistent", CancellationToken.None);

        Assert.Null(server);
    }

    [Fact]
    public async Task GetWhoisServer_CaseInsensitive_ReturnsHostname()
    {
        var registry = CreateRegistry();

        var serverLower = await registry.GetWhoisServer("com", CancellationToken.None);
        var serverUpper = await registry.GetWhoisServer("COM", CancellationToken.None);

        Assert.Equal(serverLower, serverUpper);
    }

    [Fact]
    public async Task Refresh_ResetsCache_ReloadsData()
    {
        var registry = CreateRegistry();

        // Warm cache
        await registry.GetRdapBaseUrl("com", CancellationToken.None);

        // Refresh should not throw and should reload
        await registry.Refresh(CancellationToken.None);

        var url = await registry.GetRdapBaseUrl("com", CancellationToken.None);
        Assert.NotNull(url);
    }

    [Fact]
    public async Task ParseBootstrapJson_OnlyAcceptsHttps()
    {
        const string json = """
            {
              "services": [
                [["example"], ["http://insecure.example.com/", "https://secure.example.com/"]],
                [["httponly"], ["http://httponly.example.com/"]]
              ]
            }
            """;

        var result = BootstrapRegistry.ParseBootstrapJson(json);

        Assert.True(result.ContainsKey("example"));
        Assert.Equal("https://secure.example.com/", result["example"]);
        Assert.False(result.ContainsKey("httponly"));
    }

    private static BootstrapRegistry CreateRegistry()
    {
        // Uses embedded snapshot only -- no network calls
        return new BootstrapRegistry();
    }
}
