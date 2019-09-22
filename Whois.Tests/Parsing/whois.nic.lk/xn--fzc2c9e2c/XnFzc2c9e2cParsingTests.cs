using System;
using NUnit.Framework;
using Whois.Models;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Lk.XnFzc2c9e2c
{
    [TestFixture]
    public class XnFzc2c9e2cParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.lk", "xn--fzc2c9e2c", "not_found.txt");
            var response = parser.Parse("whois.nic.lk", "xn--fzc2c9e2c", sample);

            Assert.IsNull(response);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.lk", "xn--fzc2c9e2c", "found.txt");
            var response = parser.Parse("whois.nic.lk", "xn--fzc2c9e2c", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisResponseStatus.Found, response.Status);

            AssertWriter.Write(response);
        }
    }
}
