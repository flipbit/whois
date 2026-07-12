using Spectre.Console.Cli;
using WhoisRefresh.Commands;

var app = new CommandApp();
app.Configure(config =>
{
    config.SetApplicationName("whoisrefresh");
    config.AddCommand<BootstrapCommand>("bootstrap")
        .WithDescription("Generate domains.jsonc from existing parsing tests");
});

return await app.RunAsync(args);
