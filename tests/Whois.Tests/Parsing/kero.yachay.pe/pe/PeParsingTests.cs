using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Kero.Yachay.Pe.Pe
{
    [TestFixture]
    public class PeParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("kero.yachay.pe", "pe", "throttled.txt");
            var response = parser.Parse("kero.yachay.pe", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Throttled, response.Status);
            Assert.AreEqual(1, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("kero.yachay.pe", "pe", "not_found.txt");
            var response = parser.Parse("kero.yachay.pe", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(3, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);

            Assert.AreEqual("u34jedzcq.pe", response.DomainName.ToString());

            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Not Registered", response.DomainStatus[0]);
        }

        [Test]
        public void Test_inactive()
        {
            var sample = SampleReader.Read("kero.yachay.pe", "pe", "inactive.txt");
            var response = parser.Parse("kero.yachay.pe", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotAssigned, response.Status);

            Assert.AreEqual(7, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);

            Assert.AreEqual("zumba.pe", response.DomainName.ToString());

            Assert.AreEqual("NIC .PE", response.Registrar.Name);

            Assert.AreEqual("GRUPO ALBATROS SAC", response.Registrant.Name);

            Assert.AreEqual("GRUPO ALBATROS SAC", response.AdminContact.Name);
            Assert.AreEqual("jsotelo@galbatros.com", response.AdminContact.Email);


            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Inactive", response.DomainStatus[0]);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("kero.yachay.pe", "pe", "found.txt");
            var response = parser.Parse("kero.yachay.pe", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(11, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);

            Assert.AreEqual("google.pe", response.DomainName.ToString());

            Assert.AreEqual("MarkMonitor Inc.", response.Registrar.Name);

            Assert.AreEqual("google inc.", response.Registrant.Name);

            Assert.AreEqual("MarkMonitor", response.AdminContact.Name);
            Assert.AreEqual("ccops@markmonitor.com", response.AdminContact.Email);


            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Active", response.DomainStatus[0]);        
        }

        [Test]
        public void Test_suspended()
        {
            var sample = SampleReader.Read("kero.yachay.pe", "pe", "suspended.txt");
            var response = parser.Parse("kero.yachay.pe", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Suspended, response.Status);

            Assert.AreEqual(11, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);

            Assert.AreEqual("bangladesh.pe", response.DomainName.ToString());

            Assert.AreEqual("1API GmbH", response.Registrar.Name);

            Assert.AreEqual("Ahmed Nitul", response.Registrant.Name);

            Assert.AreEqual("Ahmed Nitul", response.AdminContact.Name);
            Assert.AreEqual("ahmed@nitul.net", response.AdminContact.Email);

            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.dnsimple.com", response.NameServers[0]);
            Assert.AreEqual("ns2.dnsimple.com", response.NameServers[1]);
            Assert.AreEqual("ns3.dnsimple.com", response.NameServers[2]);
            Assert.AreEqual("ns4.dnsimple.com", response.NameServers[3]);

            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Suspended", response.DomainStatus[0]);
        }
    }
}
