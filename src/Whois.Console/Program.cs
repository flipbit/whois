using Microsoft.Extensions.DependencyInjection;
using Spectre.Console.Cli;
using Whois.Commands;
using Whois.Infrastructure;

var services = new ServiceCollection();

var registrar = new TypeRegistrar(services);
var app = new CommandApp<WhoisCommand>(registrar);

app.Configure(config =>
{
    config.SetApplicationName("dotnet-whois");
});

return await app.RunAsync(args).ConfigureAwait(false);
