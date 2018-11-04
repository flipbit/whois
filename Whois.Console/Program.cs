using Serilog;
using Whois.Commands;

namespace Whois
{
    /// <summary>
    /// WHOIS demo application
    /// </summary>
    class Program
    {
        /// <summary>
        /// Main entry point for the application.
        /// </summary>
        /// <param name="args">The args.</param>
        static void Main(string[] args)
        {
            var log = new LoggerConfiguration()
                .WriteTo
                .Console(outputTemplate: "{Timestamp:HH:mm} [{Level}] ({Name:l}) {Message}{NewLine}{Exception}")
                .WriteTo
                .RollingFile("whois-{date}.txt")
                .MinimumLevel.Debug()
                .CreateLogger();

            Log.Logger = log;

            var runner = new WhoisRunner();

            runner.Commands.Add(new WhoisCommand());
            runner.Commands.Add(new ExitCommand());
            runner.Commands.Add(new HelpCommand());
            runner.Commands.Add(new Top500Command());

            runner.Run(args);
        }
    }
}