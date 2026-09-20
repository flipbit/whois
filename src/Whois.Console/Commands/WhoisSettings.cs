using System.ComponentModel;
using Spectre.Console;
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

    [CommandOption("--timeout")]
    [Description("Query timeout in seconds")]
    public int? Timeout { get; set; }

    [CommandOption("--rdap")]
    [Description("Force RDAP protocol")]
    public bool Rdap { get; set; }

    [CommandOption("--whois")]
    [Description("Force WHOIS protocol")]
    public bool ForceWhois { get; set; }

    public override ValidationResult Validate()
    {
        if (Rdap && ForceWhois)
        {
            return ValidationResult.Error("Cannot specify both --rdap and --whois");
        }

        return ValidationResult.Success();
    }
}
