using System.Diagnostics;
using System.IO;
using System.Threading;
using NUnit.Framework;

namespace Whois
{
    [TestFixture]
    public class Downloader
    {
        private WhoisLookup lookup;

        [SetUp]
        public void SetUp()
        {
            lookup = new WhoisLookup();
        }

        [Test]
        [Ignore]
        public void DownloadTop500DomainAsSamples()
        {
            var lines = File.ReadAllLines(@"..\..\Data\top-500.txt");

            foreach (var line in lines)
            {
                Debug.WriteLine("Looking up: " + line);

                var whois = lookup.Lookup(line);

                File.WriteAllText(@"..\..\..\Whois.Tests\Samples\" + line + ".txt", whois.ToString());

                Thread.Sleep(10000);
            }
        }
    }
}
