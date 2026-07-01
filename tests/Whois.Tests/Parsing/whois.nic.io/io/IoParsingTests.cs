using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Io.Io
{
    [TestFixture]
    public class IoParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.io", "io", "found.txt");
            var response = parser.Parse("whois.nic.io", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.io/io/Found", response.TemplateName);

            Assert.AreEqual("google.io", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2013, 09, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("GOOGLE INC.", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("2400 E. Bayshore Pkwy", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("CA", response.Registrant.Address[2]);
            Assert.AreEqual("US", response.Registrant.Address[3]);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Live", response.DomainStatus[0]);

            Assert.AreEqual(13, response.FieldsParsed);
        }

        [Test]
        public void Test_reserved()
        {
            var sample = SampleReader.Read("whois.nic.io", "io", "reserved.txt");
            var response = parser.Parse("whois.nic.io", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Reserved, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.io/io/Reserved", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.nic.io", "io", "not_found.txt");
            var response = parser.Parse("whois.nic.io", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.io/io/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.io", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.nic.io", "io", "found_status_registered.txt");
            var response = parser.Parse("whois.nic.io", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.nic.io/io/Found", response.TemplateName);

            Assert.AreEqual("redis.io", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2014, 05, 28, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Salvatore Sanfilippo", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("Salvatore Sanfilippo", response.Registrant.Address[0]);
            Assert.AreEqual("Via F.Alaimo, 2", response.Registrant.Address[1]);
            Assert.AreEqual("Campobello di Licata (AG", response.Registrant.Address[2]);
            Assert.AreEqual("IT", response.Registrant.Address[3]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.iwantmyname.net", response.NameServers[0]);
            Assert.AreEqual("ns2.iwantmyname.net", response.NameServers[1]);
            Assert.AreEqual("ns3.iwantmyname.net", response.NameServers[2]);
            Assert.AreEqual("ns4.iwantmyname.net", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("Live", response.DomainStatus[0]);

            Assert.AreEqual(13, response.FieldsParsed);
        }
    }
}
