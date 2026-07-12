using Spectre.Console;

namespace WhoisRefresh.Infrastructure;

public static class ConsoleOutput
{
    public static bool IsCi => string.Equals(Environment.GetEnvironmentVariable("GITHUB_ACTIONS"), "true", StringComparison.Ordinal);

    public static void WriteInfo(string message)
    {
        if (IsCi)
            Console.WriteLine(message);
        else
            AnsiConsole.MarkupLine($"[blue]{Markup.Escape(message)}[/]");
    }

    public static void WriteSuccess(string message)
    {
        if (IsCi)
            Console.WriteLine(message);
        else
            AnsiConsole.MarkupLine($"[green]{Markup.Escape(message)}[/]");
    }

    public static void WriteWarning(string message)
    {
        if (IsCi)
            Console.WriteLine($"::warning::{message}");
        else
            AnsiConsole.MarkupLine($"[yellow]{Markup.Escape(message)}[/]");
    }

    public static void WriteError(string message)
    {
        if (IsCi)
            Console.WriteLine($"::error::{message}");
        else
            AnsiConsole.MarkupLine($"[red]{Markup.Escape(message)}[/]");
    }
}
