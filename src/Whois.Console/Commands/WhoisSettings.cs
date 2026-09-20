using System.ComponentModel;
using Spectre.Console.Cli;

namespace Whois.Commands;

[Description("Query WHOIS registration data for a domain or IP address")]
internal sealed class WhoisSettings : CommandSettings
{
    [CommandArgument(0, "<query>")]
    [Description("Domain name or IP address to look up")]
    public string Query { get; set; } = string.Empty;

    [CommandOption("-j|--json")]
    [Description("Output result as JSON")]
    public bool Json { get; set; }

    [CommandOption("-h|--host")]
    [Description("Override WHOIS server")]
    public string? Host { get; set; }

    [CommandOption("-p|--port")]
    [Description("Override port (default 43)")]
    public int? Port { get; set; }
}
