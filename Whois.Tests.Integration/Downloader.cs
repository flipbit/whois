using System;
using System.IO;
using System.Linq;
using System.Threading;
using NUnit.Framework;
using Whois.Net;
using Whois.Servers;
using Whois.Visitors;

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
                var fileName = string.Format(@"..\..\..\Whois.Tests\Samples\Domains\{0}.txt", line);

                if (File.Exists(fileName)) continue;

                var whois = lookup.Lookup(line);

                Console.WriteLine("Writing: {0}, {1:###,##0} byte(s)", line, whois.ToString().Length);

                File.WriteAllText(fileName, whois.ToString());

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

        [Test]
        [Ignore]
        public void ShowSampleStatistics()
        {
            var files = Directory.GetFiles(@"..\..\..\Whois.Tests\Samples\Domains", "*.txt");
            var visitor = new PatternExtractorVisitor();

            foreach (var file in files)
            {
                var text = File.ReadAllText(file);

                var record = new WhoisRecord(text);

                var matches = visitor.MatchPatterns(record);

                if (matches.Any())
                {
                    var match = matches.First();

                    Console.WriteLine("{0} matches: {1}", match.Replacements.Count, Path.GetFileName(file));
                }
                else
                {
                    Console.WriteLine("No matches: {0}", file);
                }
            }
        }
    }
}
