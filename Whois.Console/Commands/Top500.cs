using System;
using System.IO;
using System.Threading;
using Contastic;
using Serilog;

namespace Whois.Commands
{
    /// <summary>
    /// Looks up WHOIS information for a domain name
    /// </summary>
    public class Top500Command : Command<Top500Command.Options>
    {
        public class Options
        {
            [Parameter(Name = "top500", Required = true)]
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
        public Top500Command()
        {
            WhoisLookup = new WhoisLookup();
        }

        public override int Execute(Options parameters)
        {
            var lines = File.ReadAllLines(@"..\..\..\Data\top-500.txt");

            Log.Debug("Read {@Length} line(s)", lines.Length);

            foreach (var line in lines)
            {
                var fileName = Path.Combine(".", $@"..\..\..\..\Whois.Tests\Samples\Domains\{line}.txt");

                if (File.Exists(fileName)) continue;

                try
                {
                    var whois = WhoisLookup.Lookup(line);

                    if (whois != null)
                    {
                        Log.Debug("{Domain}: Writing {Length:###,##0} byte(s)", line, whois.Content.Length);

                        File.WriteAllText(fileName, whois.Content);
                    }
                }
                catch (WhoisException e)
                {
                    Log.Error(e, "Error looking up WHOIS for: {domain}", line);
                }

                Thread.Sleep(15000);
            }

            return 0;
        }
    }
}
