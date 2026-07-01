using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Sn.Sn
{
    [TestFixture]
    public class SnParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.sn", "sn", "not_found.txt");
            var response = parser.Parse("whois.nic.sn", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            AssertWriter.Write(response);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.sn", "sn", "found.txt");
            var response = parser.Parse("whois.nic.sn", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.sn/sn/Found", response.TemplateName);

            Assert.AreEqual("google.sn", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("registry", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2008, 05, 08, 17, 59, 38, 430, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("C4-SN", response.Registrant.RegistryId);


             // AdminContact Details
            Assert.AreEqual("C5-SN", response.AdminContact.RegistryId);


             // TechnicalContact Details
            Assert.AreEqual("C6-SN", response.TechnicalContact.RegistryId);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            Assert.AreEqual(11, response.FieldsParsed);
        }
    }
}
