using Microsoft.Extensions.DependencyInjection;
using Spectre.Console.Cli;
using WhoisRefresh.Commands;
using WhoisRefresh.Infrastructure;

var services = new ServiceCollection();
services.AddSingleton<IFileSystem, PhysicalFileSystem>();
services.AddSingleton<IDriftReporter, GhCliDriftReporter>();

var registrar = new TypeRegistrar(services);
var app = new CommandApp(registrar);

app.Configure(config =>
{
    config.SetApplicationName("whoisrefresh");
    config.AddCommand<BootstrapCommand>("bootstrap")
        .WithDescription("Generate domains.jsonc from existing parsing tests");
    config.AddCommand<DetectCommand>("detect")
        .WithDescription("Compare refresh results against baseline, detect drift");
});

return await app.RunAsync(args);
