using System.Text.Json;
using CommandLine;

namespace Whois;

internal class Program
{
    private static async Task Main(string[] args)
    {
        await Parser.Default.ParseArguments<Options>(args)
            .WithParsedAsync(RunLookup).ConfigureAwait(false);
    }

    private static async Task RunLookup(Options options)
    {
        var lookup = new WhoisLookup();

        var result = await lookup.Lookup(options.Query!).ConfigureAwait(false);

        if (options.ConvertToJson)
        {
            var json = JsonSerializer.Serialize(result.Response, new JsonSerializerOptions { WriteIndented = true });
            Console.WriteLine(json);
        }
        else
        {
            Console.WriteLine(result.RawContent);
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
