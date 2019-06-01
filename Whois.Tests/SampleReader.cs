using System.IO;

namespace Whois
{
    public class SampleReader
    {
        public string Read(string whoisServer, string tld, string sampleFileName)
        {
            var directory = Path.Join("..\\..\\..\\Samples", whoisServer, tld);
            var fileName = Path.Join(directory, sampleFileName);

            return File.ReadAllText(fileName);
        }
    }
}
