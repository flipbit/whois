using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using CommandLine;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

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
        private static async Task Main(string[] args)
        {
            var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.SetMinimumLevel(LogLevel.Trace);
                builder.AddConsole(options => options.DisableColors = true);
            });
            LogProvider.Factory = loggerFactory;

            var result = Parser
                .Default
                .ParseArguments<Options>(args);

            await result.MapResult(async x => await Run(x), Error);
        }

        private static async Task Run(Options options)
        {
            var lookup = new WhoisLookup();

            var result = await lookup.LookupAsync(options.Query);

            if (options.ConvertToJson)
            {
                result.Content = null;

                var json = JsonConvert.SerializeObject(result, Formatting.Indented);

                Console.WriteLine(json);
            }
            else
            {
                Console.WriteLine(result.Content);
            }

            lookup.Dispose();
        }

        private static Task Error(IEnumerable<Error> errors)
        {
            if (errors == null) return Task.FromResult(true);

            foreach (var error in errors)
            {
                Console.WriteLine(error.ToString());
            }

            return Task.FromResult(true);
        }

        public class Options
        {
            [Value(0, Required = true, MetaName = "Domain Name")]
            public string Query { get; set; }

            [Option('j', "json", HelpText = "Show JSON") ]
            public bool ConvertToJson { get; set; }
        }
    }
}