using NUnit.Framework;
using System;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Bnnic.Bn.Bn
{
    [TestFixture]
    public class BnParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.bnnic.bn", "bn", "not_found.txt");
            var response = parser.Parse("whois.bnnic.bn", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound002", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.bnnic.bn", "bn", "found.txt");
            var response = parser.Parse("whois.bnnic.bn", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(11, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.bnnic.bn/bn/Found", response.TemplateName);

            Assert.AreEqual("telbru.com.bn", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("TELEKOM BRUNEI BERHAD", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2014, 12, 17, 18, 7, 42), response.Updated);
            Assert.AreEqual(new DateTime(2014, 10, 7, 0, 0, 0), response.Registered);
            Assert.AreEqual(new DateTime(2015, 10, 7, 0, 0, 0), response.Expiration);

            // Registrant Details
            Assert.AreEqual("BruNet| Telekom Brunei Berhad - (BNC875T)", response.Registrant.Name);

             // AdminContact Details
            Assert.AreEqual("BruNet| Telekom Brunei Berhad - (BNC875T)", response.AdminContact.Name);

             // TechnicalContact Details
            Assert.AreEqual("BruNet| Telekom Brunei Berhad - (BNC875T)", response.TechnicalContact.Name);
            Assert.AreEqual("info@telbru.com.bn", response.TechnicalContact.Email);


            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ok", response.DomainStatus[0]);
        }
    }
}
