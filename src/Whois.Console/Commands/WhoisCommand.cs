using System.Text.Json;
using Spectre.Console.Cli;
using Whois.JsonModels;

namespace Whois.Commands;

internal sealed class WhoisCommand : AsyncCommand<WhoisSettings>
{
    protected override async Task<int> ExecuteAsync(CommandContext context, WhoisSettings settings, CancellationToken cancellationToken)
    {
        var lookup = new WhoisLookup();
        var result = await lookup.Lookup(settings.Query, cancellationToken).ConfigureAwait(false);

        if (settings.Json)
        {
            var response = new WhoisResponse(result.Response);
            var json = JsonSerializer.Serialize(response, new JsonSerializerOptions { WriteIndented = true });
            Console.WriteLine(json);
        }
        else
        {
            Console.WriteLine(result.RawContent);
        }

        return 0;
    }
}
