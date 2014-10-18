using System;
using Contastic;

namespace Whois.Commands
{
    /// <summary>
    /// Looks up WHOIS information for a domain name
    /// </summary>
    public class WhoisCommand : Command<WhoisCommand.Options>
    {
        public class Options
        {
            [Parameter(Name = "whois", Required = true)]
            public string DomainName { get; set; }
        }

        /// <summary>
        /// Gets or sets the whois lookup.
        /// </summary>
        /// <value>
        /// The whois lookup.
        /// </value>
        public WhoisLookup WhoisLookup { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="WhoisCommand"/> class.
        /// </summary>
        public WhoisCommand()
        {
            WhoisLookup = new WhoisLookup();
        }

        /// <summary>
        /// Executes the specified parameters.
        /// </summary>
        /// <param name="parameters">The parameters.</param>
        /// <returns></returns>
        /// <exception cref="System.NotImplementedException"></exception>
        public override int Execute(Options parameters)
        {
            var record = WhoisLookup.Lookup(parameters.DomainName);

            Console.WriteLine(record.ToString());

            return 0;
        }
    }
}
