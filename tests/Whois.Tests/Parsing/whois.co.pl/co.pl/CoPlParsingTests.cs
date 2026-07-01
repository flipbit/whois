using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Co.Pl.CoPl
{
    [TestFixture]
    public class CoPlParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.co.pl", "co.pl", "not_found.txt");
            var response = parser.Parse("whois.co.pl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.co.pl/co.pl/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.co.pl", "co.pl", "found.txt");
            var response = parser.Parse("whois.co.pl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.co.pl/co.pl/Found", response.TemplateName);

            Assert.AreEqual("coco.co.pl", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2010, 06, 23, 09, 41, 50, DateTimeKind.Utc), response.Updated);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.co.pl", response.NameServers[0]);
            Assert.AreEqual("ns2.co.pl", response.NameServers[1]);

            Assert.AreEqual(5, response.FieldsParsed);
        }
    }
}
