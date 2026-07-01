using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Ja.Net.AcUk
{
    [TestFixture]
    public class AcUkParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.ja.net", "ac.uk", "not_found.txt");
            var response = parser.Parse("whois.ja.net", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            AssertWriter.Write(response);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.ja.net/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.ac.uk", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.ja.net", "ac.uk", "found.txt");
            var response = parser.Parse("whois.ja.net", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.ja.net/Found", response.TemplateName);

            Assert.AreEqual("lboro.ac.uk", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Jisc Collections and Janet Limited", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2013, 03, 20, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2003, 11, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 06, 16, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Loughborough University", response.Registrant.Name);


             // AdminContact Details
            Assert.AreEqual("M S Cook", response.AdminContact.Name);
            Assert.AreEqual("+44 1509 223498", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+44 1509 223989", response.AdminContact.FaxNumber);
            Assert.AreEqual("m.s.cook@lboro.ac.uk", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("Computing Services, Loughborough University, Loughborough, Leicestershire", response.AdminContact.Address[0]);
            Assert.AreEqual("LE11 3TU", response.AdminContact.Address[1]);
            Assert.AreEqual("United Kingdom", response.AdminContact.Address[2]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("agate.lut.ac.uk", response.NameServers[0]);
            Assert.AreEqual("bgate.lut.ac.uk", response.NameServers[1]);
            Assert.AreEqual("cgate.lut.ac.uk", response.NameServers[2]);
            Assert.AreEqual("ns3.ja.net", response.NameServers[3]);

            Assert.AreEqual(18, response.FieldsParsed);
        }
    }
}
