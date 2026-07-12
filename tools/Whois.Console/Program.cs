using System.Text.Json;
using CommandLine;
using Microsoft.Extensions.Logging;

namespace Whois;

internal class Program
{
    private static async Task Main(string[] args)
    {
        await Parser.Default.ParseArguments<Options>(args)
            .WithParsedAsync(RunLookup);
    }

    private static async Task RunLookup(Options options)
    {
        using var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(LogLevel.Error);
        });

        var logger = loggerFactory.CreateLogger<WhoisLookup>();
        var whoisOptions = Microsoft.Extensions.Options.Options.Create(new WhoisOptions());
        var lookup = new WhoisLookup(whoisOptions, logger);

        var response = await lookup.Lookup(options.Query!);

        if (options.ConvertToJson)
        {
            var json = JsonSerializer.Serialize(response, new JsonSerializerOptions { WriteIndented = true });
            Console.WriteLine(json);
        }
        else
        {
            Console.WriteLine(response.Content);
        }
    }

    public class Options
    {
        [Value(0, Required = true, MetaName = "Domain Name")]
        public string? Query { get; set; }

        [Option('j', "json", HelpText = "Show JSON")]
        public bool ConvertToJson { get; set; }
    }
}
