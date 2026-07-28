using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Whois.Net;
using Whois.Parsers;
using Whois.Protocols;
using Whois.Servers;
using Whois.Templates;

namespace Whois;

public static class WhoisServiceCollectionExtensions
{
    public static IServiceCollection AddWhois(this IServiceCollection services, Action<WhoisOptions>? configure = null)
    {
        var optionsBuilder = services.AddOptions<WhoisOptions>();
        if (configure != null)
            optionsBuilder.Configure(configure);

        RegisterCoreServices(services);
        return services;
    }

    public static IServiceCollection AddWhois(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<WhoisOptions>().Bind(configuration);
        RegisterCoreServices(services);
        return services;
    }

    private static void RegisterCoreServices(IServiceCollection services)
    {
        // Template infrastructure
        services.AddHttpClient("TemplatePackProvider");

        services.AddSingleton<CacheDirectoryManager>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<WhoisOptions>>().Value;
            var dir = options.TemplateCacheDirectory ?? WhoisOptions.GetDefaultCacheDirectory();
            return new CacheDirectoryManager(dir, sp.GetRequiredService<ILogger<CacheDirectoryManager>>());
        });

        services.AddSingleton<TemplateUpdateState>();
        services.AddSingleton<ITemplatePackProvider, TemplatePackProvider>();

        services.AddSingleton<WhoisParser>(sp =>
            new WhoisParser(server => sp.GetRequiredService<ITemplatePackProvider>().GetCachedTemplatePath(server)));

        // RDAP registry cache
        services.AddHttpClient("RdapRegistryCache");
        services.AddSingleton<IRdapRegistryCache>(sp =>
        {
            var factory = sp.GetRequiredService<IHttpClientFactory>();
            var options = sp.GetRequiredService<IOptions<WhoisOptions>>().Value;
            return new RdapRegistryCache(
                factory.CreateClient("RdapRegistryCache"),
                options,
                sp.GetRequiredService<ILogger<RdapRegistryCache>>());
        });

        // IANA server lookup
        services.AddSingleton<IIanaServerLookup>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<WhoisOptions>>().Value;
            return new IanaServerLookup(
                sp.GetRequiredService<ITcpReader>(),
                options,
                sp.GetRequiredService<ILogger<IanaServerLookup>>());
        });

        // Protocol clients
        services.AddTransient<ITcpReader, TcpReader>();
        services.AddHttpClient("RdapProtocolClient")
            .ConfigurePrimaryHttpMessageHandler(NetStandardShims.CreateNonRedirectingHandler);
        services.AddTransient<IProtocolClient, WhoisProtocolClient>(sp =>
            new WhoisProtocolClient(
                sp.GetRequiredService<ITcpReader>(),
                sp.GetRequiredService<IIanaServerLookup>(),
                sp.GetRequiredService<WhoisParser>(),
                sp.GetRequiredService<IOptions<WhoisOptions>>().Value,
                sp.GetRequiredService<ILogger<WhoisProtocolClient>>()));
        services.AddTransient<IProtocolClient, RdapProtocolClient>(sp =>
        {
            var factory = sp.GetRequiredService<IHttpClientFactory>();
            return new RdapProtocolClient(
                factory.CreateClient("RdapProtocolClient"),
                sp.GetRequiredService<IRdapRegistryCache>(),
                sp.GetRequiredService<IOptions<WhoisOptions>>().Value,
                sp.GetRequiredService<ILogger<RdapProtocolClient>>());
        });

        // Orchestrator
        services.AddTransient<IWhoisLookup, WhoisLookup>(sp =>
            new WhoisLookup(
                sp.GetRequiredService<IOptions<WhoisOptions>>(),
                sp.GetRequiredService<ILogger<WhoisLookup>>(),
                sp.GetRequiredService<IRdapRegistryCache>(),
                sp.GetRequiredService<IIanaServerLookup>(),
                sp.GetRequiredService<IEnumerable<IProtocolClient>>(),
                sp.GetRequiredService<ITemplatePackProvider>()));
    }

}
