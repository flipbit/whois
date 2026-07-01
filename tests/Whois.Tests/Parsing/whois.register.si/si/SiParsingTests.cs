using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Register.Si.Si
{
    [TestFixture]
    public class SiParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.register.si", "si", "not_found.txt");
            var response = parser.Parse("whois.register.si", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.register.si/si/NotFound", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.register.si", "si", "found.txt");
            var response = parser.Parse("whois.register.si", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.register.si/si/Found", response.TemplateName);

            Assert.AreEqual("google.si", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("AOI d.o.o.", response.Registrar.Name);
            Assert.AreEqual("http://www.aoi.eu/arneswhois", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2005, 04, 04, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2015, 07, 19, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("G79455", response.Registrant.RegistryId);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(3, response.DomainStatus.Count);
            Assert.AreEqual("server_delete_prohibited", response.DomainStatus[0]);
            Assert.AreEqual("server_transfer_prohibited", response.DomainStatus[1]);
            Assert.AreEqual("server_update_prohibited", response.DomainStatus[2]);

            Assert.AreEqual(12, response.FieldsParsed);
        }
    }
}
