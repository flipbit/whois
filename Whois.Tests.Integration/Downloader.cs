using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using NUnit.Framework;
using Whois.Net;
using Whois.Servers;

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

                Thread.Sleep(60000);
            }
        }

        [Test]
        [Ignore]
        public void DownloadTldsAsSamples()
        {
            var lines = File.ReadAllLines(@"..\..\Data\tlds.txt");
            var serverLookup = new IanaServerLookup();
            serverLookup.TcpReaderFactory = new TcpReaderFactory();

            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                if (line.StartsWith("#")) continue;

                var fileName = @"..\..\..\Whois.Tests\Samples\Tlds\" + line.ToLower() + ".txt";

                if (File.Exists(fileName)) continue;
 
                var tld = serverLookup.Lookup(line.ToLower()) as WhoisServerRecord;

                File.WriteAllText(fileName, tld.RawResponse);
                Console.WriteLine("{0}: {1:####,##0} byte(s)", line.ToLower(), tld.RawResponse.Length);

                Thread.Sleep(60000);
            }
        }
    }
}
