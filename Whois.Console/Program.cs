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
            var runner = new WhoisRunner();

            runner.Commands.Add(new WhoisCommand());
            runner.Commands.Add(new ExitCommand());
            runner.Commands.Add(new HelpCommand());

            runner.Run(args);
        }
    }
}