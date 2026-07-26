using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Whois.Net;
using Whois.Parsers;
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
        services.AddHttpClient("TemplatePackProvider");

        services.AddSingleton<CacheDirectoryManager>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<WhoisOptions>>().Value;
            var dir = options.TemplateCacheDirectory ?? GetDefaultCacheDirectory();
            return new CacheDirectoryManager(dir, sp.GetRequiredService<ILogger<CacheDirectoryManager>>());
        });

        services.AddSingleton<TemplateUpdateState>();
        services.AddSingleton<ITemplatePackProvider, TemplatePackProvider>();

        services.AddSingleton<WhoisParser>(sp =>
            new WhoisParser(server => sp.GetRequiredService<ITemplatePackProvider>().GetCachedTemplatePath(server)));

        services.AddTransient<ITcpReader, TcpReader>();
        services.AddTransient<IWhoisLookup, WhoisLookup>();
    }

    private static string GetDefaultCacheDirectory() =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Whois",
            "templates");
}
