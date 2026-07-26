namespace Whois;

public class SampleReader
{
    // CA1822: method intentionally non-static  -  inherited subclasses call it via 'SampleReader' property
#pragma warning disable CA1822
    public string Read(string whoisServer, string tld, string status, string sampleFileName)
#pragma warning restore CA1822
    {
        var directory = Path.Combine("..", "..", "..", "Samples", whoisServer, tld, status);
        var fileName = Path.Combine(directory, sampleFileName);

        return File.ReadAllText(fileName);
    }
}
