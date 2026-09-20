using System.Text.Json;
using Spectre.Console.Cli;
using Whois.JsonModels;

namespace Whois.Commands;

internal sealed class WhoisCommand : AsyncCommand<WhoisSettings>
{
    private readonly IWhoisLookup _lookup;

    public WhoisCommand(IWhoisLookup lookup)
    {
        _lookup = lookup;
    }

    protected override async Task<int> ExecuteAsync(CommandContext context, WhoisSettings settings, CancellationToken cancellationToken)
    {
        var request = new WhoisRequest(settings.Query)
        {
            WhoisServer = settings.Host != null ? new HostName(settings.Host) : null,
            Port = settings.Port,
        };

        var result = await _lookup.Lookup(request, cancellationToken).ConfigureAwait(false);

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
