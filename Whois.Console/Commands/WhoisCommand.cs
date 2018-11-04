using System;
using Contastic;
using Newtonsoft.Json;
using Whois.JsonModels;

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

            [Flag("json")]
            public bool Json { get; set; } 
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

        public override int Execute(Options parameters)
        {
            WhoisLookup.AddPattern("hello", "test");

            var record = WhoisLookup.Lookup(parameters.DomainName);

            if (parameters.Json)
            {
                if (record.ParsedResponse != null)
                {
                    var json = JsonConvert.SerializeObject(new WhoisResponse(record.ParsedResponse), Formatting.Indented);
                    Console.WriteLine(json);
                }
                else
                {
                    Console.WriteLine("Unable to parse WHOIS response:");
                    Console.WriteLine(record.Content);
                }
            }
            else
            {
                Console.WriteLine(record.Content);
            }

            return 0;
        }
    }
}
