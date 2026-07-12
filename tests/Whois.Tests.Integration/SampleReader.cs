using System.Text.Json;
using Whois.Models;

namespace Whois;

internal class SampleReader
{
    // CA1822: method intentionally non-static — called via instance in test classes
#pragma warning disable CA1822
    public List<SampleDomain> ReadSampleDomains()
#pragma warning restore CA1822
    {
        var json = File.ReadAllText(Path.Join("..\\..\\..\\Samples", "Domains.txt"));

        return JsonSerializer.Deserialize<List<SampleDomain>>(json);
    }
}
