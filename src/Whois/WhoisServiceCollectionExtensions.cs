using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Whois.Net;
using Whois.Servers;

namespace Whois;

public static class WhoisServiceCollectionExtensions
{
    public static IServiceCollection AddWhois(this IServiceCollection services, Action<WhoisOptions>? configure = null)
    {
        var optionsBuilder = services.AddOptions<WhoisOptions>();
        if (configure != null)
            optionsBuilder.Configure(configure);

        services.AddTransient<ITcpReader, TcpReader>();
        services.AddTransient<IWhoisServerLookup, IanaServerLookup>();
        services.AddTransient<IWhoisLookup, WhoisLookup>();
        return services;
    }

    public static IServiceCollection AddWhois(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<WhoisOptions>().Bind(configuration);
        services.AddTransient<ITcpReader, TcpReader>();
        services.AddTransient<IWhoisServerLookup, IanaServerLookup>();
        services.AddTransient<IWhoisLookup, WhoisLookup>();
        return services;
    }
}
