using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Hu.Hu
{
    [TestFixture]
    public class HuParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.hu", "hu", "not_found.txt");
            var response = parser.Parse("whois.nic.hu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.hu/hu/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.hu", "hu", "found.txt");
            var response = parser.Parse("whois.nic.hu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.hu/hu/Found", response.TemplateName);

            Assert.AreEqual("google.hu", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2000, 03, 25, 23, 20, 39, 000, DateTimeKind.Utc), response.Registered);

            Assert.AreEqual(3, response.FieldsParsed);
        }
    }
}
