using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Ci.Ci
{
    [TestFixture]
    public class CiParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.ci", "ci", "not_found.txt");
            var response = parser.Parse("whois.nic.ci", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.ci/ci/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.ci", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.ci", "ci", "found.txt");
            var response = parser.Parse("whois.nic.ci", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.ci/ci/Found", response.TemplateName);

            Assert.AreEqual("google.ci", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("afriregister", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2006, 01, 27, 11, 14, 47, 770, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2014, 02, 14, 11, 14, 47, 770, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("DG181-NICCI", response.Registrant.RegistryId);


             // AdminContact Details
            Assert.AreEqual("DG181-NICCI", response.AdminContact.RegistryId);


             // TechnicalContact Details
            Assert.AreEqual("DG181-NICCI", response.TechnicalContact.RegistryId);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            Assert.AreEqual(12, response.FieldsParsed);
        }
    }
}
