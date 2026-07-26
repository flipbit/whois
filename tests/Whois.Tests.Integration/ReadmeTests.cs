using System.Text;
using Xunit;

namespace Whois;

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
        var result = await whois.Lookup("github.com");

        // Output the response
        Console.WriteLine(result.RawContent);
    }

    [Fact]
    public async Task TestParsedLookup()
    {
        // Create a WhoisLookup instance
        var whois = new WhoisLookup();

        // Query github.com
        var result = await whois.Lookup("github.com");

        // Convert the response to JSON
        var json = System.Text.Json.JsonSerializer.Serialize(result.Response, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });

        // Output the json
        Console.WriteLine(json);
    }

    [Fact]
    public async Task TestAsyncLookup()
    {
        // Create a WhoisLookup instance
        var whois = new WhoisLookup();

        // Query github.com
        var result = await whois.Lookup("github.com");

        // Output the response
        Console.WriteLine(result.RawContent);
    }

    [Fact]
    public void TestConfiguration()
    {
        // Per-instance configuration
        var lookup = new WhoisLookup(new WhoisOptions { Encoding = Encoding.UTF8 });
        Assert.Equal(Encoding.UTF8, lookup.Options.Encoding);
    }
}
