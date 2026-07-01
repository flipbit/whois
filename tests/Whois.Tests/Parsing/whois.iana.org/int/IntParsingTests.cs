using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Iana.Org.Int
{
    [TestFixture]
    public class IntParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.iana.org", "int", "not_found.txt");
            var response = parser.Parse("whois.iana.org", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.iana.org/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.int", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.iana.org", "int", "found.txt");
            var response = parser.Parse("whois.iana.org", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.iana.org/Found01", response.TemplateName);

            Assert.AreEqual("nato.int", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2012, 08, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1997, 08, 26, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("North Atlantic Treaty Organization", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Blvd Leopold III", response.Registrant.Address[0]);
            Assert.AreEqual("1110 Brussels", response.Registrant.Address[1]);
            Assert.AreEqual("Brussels", response.Registrant.Address[2]);
            Assert.AreEqual("Belgium", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("Aidan Murdock", response.AdminContact.Name);
            Assert.AreEqual("+32 65 44 9168", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+32 65 44 9480", response.AdminContact.FaxNumber);
            Assert.AreEqual("aidan.murdock@ncia.nato.int", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("SHAPE", response.AdminContact.Address[0]);
            Assert.AreEqual("NCIA SP SDD SAS NAR", response.AdminContact.Address[1]);
            Assert.AreEqual("Mons Hainaut 7010", response.AdminContact.Address[2]);
            Assert.AreEqual("Belgium", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("Francesco Conserva", response.TechnicalContact.Name);
            Assert.AreEqual("+32 65 44 7534", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+32 65 44 7556", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("francesco.conserva@ncia.nato.int", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("SHAPE", response.TechnicalContact.Address[0]);
            Assert.AreEqual("NCIA SP SMD ENT EMA", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Mons Hainaut 7010", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Belgium", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(7, response.NameServers.Count);
            Assert.AreEqual("globe.nc3a.nato.int", response.NameServers[0]);
            Assert.AreEqual("max.nra.nato.int", response.NameServers[1]);
            Assert.AreEqual("maxima.nra.nato.int", response.NameServers[2]);
            Assert.AreEqual("ns.namsa.nato.int", response.NameServers[3]);
            Assert.AreEqual("ns.saclantc.nato.int", response.NameServers[4]);
            Assert.AreEqual("ns1.cs.ucl.ac.uk", response.NameServers[5]);
            Assert.AreEqual("ns1.drenet.dnd.ca", response.NameServers[6]);

            Assert.AreEqual(32, response.FieldsParsed);
        }
    }
}
