using System;
using Contastic;

namespace Whois.Commands
{
    /// <summary>
    /// Displays help information
    /// </summary>
    public class HelpCommand : Command<HelpCommand.Options>
    {
        [Flag("help")]
        public class Options {}

        /// <summary>
        /// Executes the specified parameters.
        /// </summary>
        /// <param name="parameters">The parameters.</param>
        /// <returns></returns>
        /// <exception cref="System.NotImplementedException"></exception>
        public override int Execute(Options parameters)
        {
            Console.WriteLine("Available commands:");
            Console.WriteLine("");
            Console.WriteLine("help             - Displays this text");
            Console.WriteLine("whois [domain]   - Displays WHOIS information for a specific domain");

            return 0;
        }
    }
}
