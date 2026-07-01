using System.IO;

namespace Whois
{
    public class SampleReader
    {
        public string Read(string whoisServer, string tld, string sampleFileName)
        {
            var directory = Path.Combine("..", "..", "..", "Samples", whoisServer, tld);
            var fileName = Path.Combine(directory, sampleFileName);

            return File.ReadAllText(fileName);
        }
    }
}
