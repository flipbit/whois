using System;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using NUnit.Framework;
using Whois.Net;

namespace Whois
{
    /// <summary>
    /// Example code for the README.md on Github
    /// </summary>
    [TestFixture]
    public class ReadmeTests
    {
        [Test]
        public void TestBasicLookup()
        {
            // Create a WhoisLookup instance
            var whois = new WhoisLookup();

            // Query github.com
            var response = whois.Lookup("github.com");

            // Output the response
            Console.WriteLine(response.Content);
        }

        [Test]
        public void TestParsedLookup()
        {
            // Create a WhoisLookup instance
            var whois = new WhoisLookup();

            // Query github.com
            var response = whois.Lookup("github.com");

            // Convert the response to JSON
            var json = JsonConvert.SerializeObject(response, Formatting.Indented);

            // Output the json 
            Console.WriteLine(json);
        }

        [Test]
        public async Task TestAsyncLookup()
        {
            // Create a WhoisLookup instance
            var whois = new WhoisLookup();

            // Query github.com
            var response = await whois.LookupAsync("github.com");

            // Output the response 
            Console.WriteLine(response.Content);
        }

        [Test]
        public void TestConfiguration()
        {
            // Global configuration
            WhoisOptions.Defaults.Encoding = Encoding.UTF8;

            // Per-instance configuration
            var lookup = new WhoisLookup();
            lookup.Options.TimeoutSeconds = 30;
        }

        [Test]
        public void TestParsing()
        {
            var lookup = new WhoisLookup();

            // Clear the embedded templates (not recommended)
            lookup.Parser.ClearTemplates();

            // Add a custom WHOIS response parsing template
            lookup.Parser.AddTemplate("Domain: { DomainName$ }", "Simple Pattern");
        }

        private class MyCustomTcpReader : ITcpReader
        {
            private readonly ITcpReader reader;

            public MyCustomTcpReader()
            {
                reader = new TcpReader();
            }

            public Task<string> Read(string url, int port, string command, Encoding encoding, int timeoutSeconds)
            {
                Console.WriteLine($"Reading from URL: {url}");

                return reader.Read(url, port, command, encoding, timeoutSeconds);
            }

            public void Dispose()
            {
                reader.Dispose();
            }
        }

        [Test]
        public void TestCustomNetworking()
        {
            // Create a WhoisLookup instance
            var lookup = new WhoisLookup();

            // Assign the custom TcpReader
            lookup.TcpReader = new MyCustomTcpReader();

            // Lookups will now use the custom TcpReader
            var response = lookup.Lookup("github.com");

            Console.WriteLine(response.Content);
        }
    }
}
