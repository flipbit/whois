using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Registre.Ma.Ma
{
    [TestFixture]
    public class MaParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.registre.ma", "ma", "not_found.txt");
            var response = parser.Parse("whois.registre.ma", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.registre.ma/ma/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.registre.ma", "ma", "found.txt");
            var response = parser.Parse("whois.registre.ma", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.registre.ma/ma/Found", response.TemplateName);

            Assert.AreEqual("google.ma", response.DomainName.ToString());
            Assert.AreEqual("333.google.ma", response.RegistryDomainId);

            Assert.AreEqual(new DateTime(2009, 03, 24, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2009, 03, 24, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("221.google.ma", response.Registrant.RegistryId);


             // AdminContact Details
            Assert.AreEqual("222.google.ma", response.AdminContact.RegistryId);


             // BillingContact Details
            Assert.AreEqual("222.google.ma", response.BillingContact.RegistryId);


             // TechnicalContact Details
            Assert.AreEqual("223.google.ma", response.TechnicalContact.RegistryId);


            Assert.AreEqual(9, response.FieldsParsed);
        }
    }
}
