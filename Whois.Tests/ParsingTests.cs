using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Resources;
using NUnit.Framework;
using Tokens;
using Whois.Models;
using Whois.Visitors;

namespace Whois
{
    [TestFixture]
    public class ParsingTests
    {
        [Test]
        public void TestParseSampleDomains()
        {
            var results = new List<SampleParseResult>();

            var sampleFileNames = Directory.EnumerateFiles(@"../../../Samples/Domains", "*.txt");

            foreach (var sampleFileName in sampleFileNames)
            {
                var fullFileName = Path.Join(Directory.GetCurrentDirectory(), sampleFileName);

                var result = new SampleParseResult
                {
                    Contents = File.ReadAllText(fullFileName),
                    FullFileName = fullFileName
                };

                results.Add(result);
            }

            var visitor = new PatternExtractorVisitor();

            foreach (var result in results)
            {
                result.ContentParsed = visitor.Parse(result.Contents);
            }

            foreach (var result in results.Where(r => r.ContentParsed.Success == true).OrderBy(r => r.ContentParsed.BestMatch?.Tokens.Matches.Count))
            {
                Console.WriteLine(result.DomainName);
            }
        }

        private class SampleParseResult
        {
            public string FullFileName { get; set; }

            public string DomainName
            {
                get
                {
                    var fileName = Path.GetFileName(FullFileName);

                    return Path
                        .GetFileNameWithoutExtension(fileName)
                        .ToLowerInvariant();
                }
            }

            public string Contents { get; set; }

            public TokenMatcherResult<ParsedWhoisResponse> ContentParsed { get; set; }
        }
    }
}
