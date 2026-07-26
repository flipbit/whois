using Microsoft.Extensions.DependencyInjection;
using Spectre.Console.Cli;
using Whois.Net;
using Whois.Refresh.Commands;
using Whois.Refresh.Infrastructure;

var services = new ServiceCollection();
services.AddSingleton<IFileSystem, PhysicalFileSystem>();
services.AddSingleton<IDriftReporter, GhCliDriftReporter>();
services.AddSingleton<ITcpReader, TcpReader>();

var registrar = new TypeRegistrar(services);
var app = new CommandApp(registrar);

app.Configure(config =>
{
    config.SetApplicationName("whoisrefresh");
    config.AddCommand<BootstrapCommand>("bootstrap")
        .WithDescription("Generate domains.jsonc from existing parsing tests");
    config.AddCommand<RefreshCommand>("refresh")
        .WithDescription("Query live WHOIS servers and save responses");
    config.AddCommand<DetectCommand>("detect")
        .WithDescription("Compare refresh results against baseline, detect drift");
    config.AddCommand<PackageCommand>("package")
        .WithDescription("Build a versioned template pack zip with manifest");
});

return await app.RunAsync(args).ConfigureAwait(false);
