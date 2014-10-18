using System;
using Contastic;

namespace Whois
{
    /// <summary>
    /// Main command runner for the WHOIS application
    /// </summary>
    public class WhoisRunner : InteractiveCommandRunner
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisRunner"/> class.
        /// </summary>
        public WhoisRunner()
        {
            Console.WriteLine("WHOIS Console.  Type 'help' for help, or 'exit' to exit.");
        }

        /// <summary>
        /// Prompts this instance.
        /// </summary>
        public override void Prompt()
        {
            Console.Write("WHOIS>");
        }
    }
}
