using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Eenet.Ee.Ee
{
    [TestFixture]
    public class EeParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.eenet.ee", "ee", "not_found.txt");
            var response = parser.Parse("whois.eenet.ee", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.eenet.ee/ee/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.ee", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.eenet.ee", "ee", "found.txt");
            var response = parser.Parse("whois.eenet.ee", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.eenet.ee/ee/Found", response.TemplateName);

            Assert.AreEqual("google.ee", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2010, 05, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2003, 04, 22, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("ADVOKAADIBÜROO SORAINEN AS", response.Registrant.Name);
            Assert.AreEqual("5274536", response.Registrant.TelephoneNumber);
            Assert.AreEqual("+372 6400 901", response.Registrant.FaxNumber);

             // Registrant Address
            Assert.AreEqual(1, response.Registrant.Address.Count);
            Assert.AreEqual("PÄRNU MNT, 15, HARJUMAA TALLINN KESKLINN 10141", response.Registrant.Address[0]);


             // AdminContact Details
            Assert.AreEqual("Mart Meier", response.AdminContact.Name);
            Assert.AreEqual("mart.meier@sorainen.ee", response.AdminContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("Joshua Hopping", response.TechnicalContact.Name);
            Assert.AreEqual("ccops@markmonitor.com", response.TechnicalContact.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);

            Assert.AreEqual(14, response.FieldsParsed);
        }
    }
}
