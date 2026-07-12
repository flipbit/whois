namespace Whois;

public class SampleReader
{
    public string Read(string whoisServer, string tld, string status, string sampleFileName)
    {
        var directory = Path.Combine("..", "..", "..", "Samples", whoisServer, tld, status);
        var fileName = Path.Combine(directory, sampleFileName);

        return File.ReadAllText(fileName);
    }
}
