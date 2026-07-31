using System.Collections.Concurrent;
using Xunit;

namespace Whois.Parsers;

public class WhoisParserCacheTests : IDisposable
{
    private readonly string _tempDir;

    public WhoisParserCacheTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"whois-parser-tests-{Guid.NewGuid()}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, recursive: true);
    }

    private void WriteTemplate(string subdirectory, string fileName, string serverTag)
    {
        var dir = Path.Combine(_tempDir, subdirectory);
        Directory.CreateDirectory(dir);
        var content = string.Join('\n',
            "---",
            $"name: {subdirectory}/found/01",
            $"tag: {serverTag}",
            "set: Status = Found",
            "---",
            "Domain Name: { DomainName }");
        File.WriteAllText(Path.Combine(dir, fileName), content);
    }

    [Fact]
    public void LoadServerTemplatesFromDirectory_LoadsTemplatesFromDisk()
    {
        const string serverTag = "whois.test.example";
        WriteTemplate("whois.test.example", "found.txt", serverTag);

        var parser = new WhoisParser();
        parser.LoadServerTemplatesFromDirectory(serverTag, Path.Combine(_tempDir, "whois.test.example"));

        Assert.True(parser.Templates.ContainsTag(serverTag));
    }

    [Fact]
    public async Task Parse_ConcurrentCalls_ThreadSafe()
    {
        var servers = new[] { "whois.iana.org", "whois.ja.net" };

        var parser = new WhoisParser();
        var exceptions = new ConcurrentBag<Exception>();

        var tasks = Enumerable.Range(0, 20).Select(i =>
            Task.Run(() =>
            {
                var server = servers[i % servers.Length];
                parser.Parse(server, "domain: test");
            })).ToArray();

        await Task.WhenAll(tasks);

        Assert.Empty(exceptions);
    }
}
