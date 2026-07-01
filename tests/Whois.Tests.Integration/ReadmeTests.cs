using System;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using Whois.Net;

namespace Whois
{
    /// <summary>
    /// Example code for the README.md on Github
    /// </summary>
    public class ReadmeTests
    {
        [Fact]
        public async Task TestBasicLookup()
        {
            // Create a WhoisLookup instance
            var whois = new WhoisLookup();

            // Query github.com
            var response = await whois.Lookup("github.com");

            // Output the response
            Console.WriteLine(response.Content);
        }

        [Fact]
        public async Task TestParsedLookup()
        {
            // Create a WhoisLookup instance
            var whois = new WhoisLookup();

            // Query github.com
            var response = await whois.Lookup("github.com");

            // Convert the response to JSON
            var json = System.Text.Json.JsonSerializer.Serialize(response, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });

            // Output the json
            Console.WriteLine(json);
        }

        [Fact]
        public async Task TestAsyncLookup()
        {
            // Create a WhoisLookup instance
            var whois = new WhoisLookup();

            // Query github.com
            var response = await whois.Lookup("github.com");

            // Output the response
            Console.WriteLine(response.Content);
        }

        [Fact]
        public void TestConfiguration()
        {
            // Per-instance configuration
            var lookup = new WhoisLookup(new WhoisOptions { Encoding = Encoding.UTF8 });
            lookup.Options.TimeoutSeconds = 30;
        }

        [Fact]
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

            public Task<string> Read(string url, int port, string command, Encoding encoding, int timeoutSeconds, System.Threading.CancellationToken cancellationToken = default)
            {
                Console.WriteLine($"Reading from URL: {url}");

                return reader.Read(url, port, command, encoding, timeoutSeconds, cancellationToken);
            }
        }

        [Fact]
        public async Task TestCustomNetworking()
        {
            // Create a WhoisLookup instance
            var lookup = new WhoisLookup();

            // Assign the custom TcpReader
            lookup.TcpReader = new MyCustomTcpReader();

            // Lookups will now use the custom TcpReader
            var response = await lookup.Lookup("github.com");

            Console.WriteLine(response.Content);
        }
    }
}
