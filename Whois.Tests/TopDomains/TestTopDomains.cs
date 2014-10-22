using System;
using System.Collections.Generic;
using System.IO;
using NUnit.Framework;
using Whois.Visitors;

namespace Whois.TopDomains
{
    [TestFixture]
    public class TestTopDomains
    {
        [Test]
        public void TestParseTopDomains()
        {
            var fails = new List<string>();
            var files = Directory.GetFiles("..\\..\\Samples", "*.txt");

            var visitor = new PatternExtractorVisitor();

            foreach (var file in files)
            {
                var text = File.ReadAllText(file);

                var record = new WhoisRecord(text);

                var matches = visitor.MatchPatterns(record);

                if (matches[0].Replacements.Count == 0)
                {
                    fails.Add(file);
                }
                else
                {
                    Console.WriteLine("{0} replacement(s) made in {1}", matches[0].Replacements.Count, file);
                }
            }

            foreach (var fail in fails)
            {
                Console.WriteLine("No replacements made in: {0}", fail);
            }

            if (fails.Count > 0)
            {
                Assert.Fail("No replacements made for some files, check output!");
            }
        }
    }
}
