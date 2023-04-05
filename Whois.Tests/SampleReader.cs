using System.IO;

namespace Whois
{
    public class SampleReader
    {
        public string Read(string whoisServer, string tld, string sampleFileName)
        {
            var sampleDirectory = Path.GetFullPath(Path.Join("..", "..", "..", "Samples"));
            var directory = Path.Join(sampleDirectory, whoisServer, tld);
            var fileName = Path.Join(directory, sampleFileName);

            return File.ReadAllText(fileName);
        }
    }
}
