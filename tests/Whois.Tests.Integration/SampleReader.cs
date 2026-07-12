using System.Text.Json;
using Whois.Models;

namespace Whois;

internal class SampleReader
{
    public List<SampleDomain> ReadSampleDomains()
    {
        var json = File.ReadAllText(Path.Join("..\\..\\..\\Samples", "Domains.txt"));

        return JsonSerializer.Deserialize<List<SampleDomain>>(json);
    }
}
