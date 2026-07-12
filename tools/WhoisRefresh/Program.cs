using Spectre.Console.Cli;

var app = new CommandApp();
app.Configure(config =>
{
    config.SetApplicationName("whoisrefresh");
});

return await app.RunAsync(args);
