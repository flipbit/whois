using System;
using Contastic;

namespace Whois.Commands
{
    /// <summary>
    /// Exits the application
    /// </summary>
    public class ExitCommand : Command<ExitCommand.Options>
    {
        [Flag("exit")]
        public class Options {}

        /// <summary>
        /// Executes the specified parameters.
        /// </summary>
        /// <param name="parameters">The parameters.</param>
        /// <returns></returns>
        /// <exception cref="System.NotImplementedException"></exception>
        public override int Execute(Options parameters)
        {
            Environment.Exit(0);

            return 0;
        }
    }
}
