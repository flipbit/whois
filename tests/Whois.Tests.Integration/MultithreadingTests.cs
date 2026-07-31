using System.Collections.Concurrent;
using Xunit;
using Whois.Models;

namespace Whois;

public class MultithreadingTests
{
    private readonly WhoisLookup lookup;

    public MultithreadingTests()
    {
        lookup = new WhoisLookup();
    }

    [Fact]
    public async Task TestDownloadSampleDomainsSingleThreaded()
    {
        var domains = new SampleReader().ReadSampleDomains();

        foreach (var domain in domains)
        {
            Console.WriteLine($"Looking Up: {domain.DomainName}");

            try
            {
                var result = await lookup.Lookup(domain.DomainName);

                Console.WriteLine($"Looked Up: {domain.DomainName}, Protocol: {result.Protocol}, Size: {result.RawContent.Length}");
            }
#pragma warning disable CA1031 // Catch-all: integration test continues on any network/parse error
            catch (Exception e)
#pragma warning restore CA1031
            {
                Console.WriteLine($"FAIL: {domain.DomainName}: {e.Message}");
            }
            Thread.Sleep(1000);
        }
    }

    [Fact]
    public async Task TestDownloadSamplesDomainsMultipleThreaded()
    {
        var domains = new SampleReader().ReadSampleDomains();

        var queue = new ConcurrentQueue<SampleDomain>(domains);
        var responses = new ConcurrentBag<LookupResult<DomainInfo>>();

        var tasks = Enumerable.Range(1, 25).Select(async i =>
        {
            while (queue.IsEmpty == false)
            {
                if (!queue.TryDequeue(out var domain)) continue;

                Console.WriteLine($"Looking Up: {domain.DomainName}");

                try
                {
                    var result = await lookup.Lookup(domain.DomainName).ConfigureAwait(false);

                    if (result != null)
                    {
                        responses.Add(result);
                    }
                    else
                    {
                        Console.WriteLine($"NULL: {domain.DomainName}");
                    }
                }
#pragma warning disable CA1031 // Catch-all: integration test continues on any network/parse error
                catch (Exception e)
#pragma warning restore CA1031
                {
                    Console.WriteLine($"FAIL: {domain.DomainName}: {e.Message}");
                }
            }
        });

        await Task.WhenAll(tasks);

        foreach (var result in responses)
        {
            Console.WriteLine($"Looked Up: {result.Response.DomainName}, Protocol: {result.Protocol}, Size: {result.RawContent.Length}");
        }
    }
}
