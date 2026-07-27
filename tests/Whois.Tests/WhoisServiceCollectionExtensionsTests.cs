using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Whois.Net;
using Whois.Parsers;
using Whois.Protocols;
using Whois.Templates;
using Xunit;

namespace Whois;

public class WhoisServiceCollectionExtensionsTests
{
    [Fact]
    public void AddWhois_RegistersServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddWhois();
        var provider = services.BuildServiceProvider();

        Assert.NotNull(provider.GetService<IWhoisLookup>());
        Assert.NotNull(provider.GetService<ITcpReader>());
        // IWhoisServerLookup removed in Task 3 refactor -- server discovery is handled by protocol clients (Task 6+)
    }

    [Fact]
    public void AddWhois_WithConfigure_SetsOptions()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddWhois(options =>
        {
            options.TimeoutSeconds = 30;
            options.FollowReferrer = false;
        });
        var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<IOptions<WhoisOptions>>();
        Assert.Equal(30, options.Value.TimeoutSeconds);
        Assert.False(options.Value.FollowReferrer);
    }

    [Fact]
    public void AddWhois_RegistersTemplatePackProvider()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddWhois();
        var provider = services.BuildServiceProvider();

        var packProvider = provider.GetService<ITemplatePackProvider>();
        Assert.NotNull(packProvider);
    }

    [Fact]
    public void AddWhois_TemplatePackProviderIsSingleton()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddWhois();
        var provider = services.BuildServiceProvider();

        var first = provider.GetRequiredService<ITemplatePackProvider>();
        var second = provider.GetRequiredService<ITemplatePackProvider>();

        Assert.Same(first, second);
    }

    [Fact]
    public void AddWhois_RegistersWhoisParser()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddWhois();
        var provider = services.BuildServiceProvider();

        var parser = provider.GetService<WhoisParser>();
        Assert.NotNull(parser);
    }

    [Fact]
    public void AddWhois_WhoisParserIsSingleton()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddWhois();
        var provider = services.BuildServiceProvider();

        var first = provider.GetRequiredService<WhoisParser>();
        var second = provider.GetRequiredService<WhoisParser>();

        Assert.Same(first, second);
    }

    [Fact]
    public void AddWhois_RegistersBothProtocolClients()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddWhois();
        var provider = services.BuildServiceProvider();

        var protocolClients = provider.GetRequiredService<IEnumerable<IProtocolClient>>().ToList();

        Assert.NotEmpty(protocolClients);
        Assert.Equal(2, protocolClients.Count);
        Assert.Single(protocolClients.OfType<WhoisProtocolClient>());
        Assert.Single(protocolClients.OfType<RdapProtocolClient>());
    }
}
