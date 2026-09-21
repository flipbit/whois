using Spectre.Console;
using Spectre.Console.Cli;
using Spectre.Console.Cli.Help;
using Spectre.Console.Rendering;

namespace Whois.Infrastructure;

/// <summary>
/// Custom help provider that removes the "-h" short form from the built-in help option.
/// This frees "-h" for use as the "--host" flag, matching unix whois convention.
/// Help remains accessible via "--help".
/// </summary>
internal sealed class WhoisHelpProvider : HelpProvider
{
    public WhoisHelpProvider(ICommandAppSettings settings) : base(settings)
    {
    }

    public override IEnumerable<IRenderable> GetOptions(ICommandModel model, ICommandInfo? command)
    {
        var parameters = command?.Parameters ?? model.DefaultCommand?.Parameters;
        if (parameters == null)
        {
            return base.GetOptions(model, command);
        }

        var options = parameters.OfType<ICommandOption>().Where(o => !o.IsHidden).ToList();
        if (options.Count == 0)
        {
            return Array.Empty<IRenderable>();
        }

        var result = new List<IRenderable>
        {
            new Markup(Environment.NewLine + "OPTIONS:" + Environment.NewLine),
        };

        var grid = new Grid();
        grid.AddColumn(new GridColumn { Padding = new Padding(4, 4), NoWrap = true });
        grid.AddColumn(new GridColumn { Padding = new Padding(0, 0) });

        // Add the built-in --help option (without -h, which is used for --host)
        grid.AddRow(new Markup("    --help"), new Markup("Prints help information"));

        foreach (var option in options)
        {
            var nameParts = BuildOptionName(option.ShortNames.ToList(), option.LongNames, option.ValueName, option.ValueIsOptional);
            var description = option.Description ?? string.Empty;

            grid.AddRow(new Markup(Markup.Escape(nameParts)), new Markup(Markup.Escape(description)));
        }

        result.Add(grid);
        return result;
    }

    private static string BuildOptionName(
        List<string> shortNames,
        IReadOnlyList<string> longNames,
        string? valueName,
        bool? valueIsOptional)
    {
        var parts = new List<string>();

        if (shortNames.Count > 0)
        {
            parts.Add("-" + shortNames[0]);
            if (longNames.Count > 0)
            {
                parts.Add(", ");
            }
        }
        else if (longNames.Count > 0)
        {
            parts.Add("    ");
        }

        if (longNames.Count > 0)
        {
            parts.Add("--" + longNames[0]);
        }

        if (valueName != null)
        {
            parts.Add(valueIsOptional is true ? $" [{valueName}]" : $" <{valueName}>");
        }

        return string.Concat(parts);
    }
}
