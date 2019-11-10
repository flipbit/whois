using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Audns.Net.Au.Au
{
    [TestFixture]
    public class AuParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.audns.net.au", "au", "found.txt");
            var response = parser.Parse("whois.audns.net.au", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(15, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.audns.net.au/au/Found", response.TemplateName);

            Assert.AreEqual("pinewood.com.au", response.DomainName.ToString());

            Assert.AreEqual("Melbourne IT", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2010, 10, 11, 0, 0, 33), response.Updated);
            Assert.AreEqual("ACN 120 562 905", response.Registrant.RegistryId);
            Assert.AreEqual("PINEWOOD PROLAB PTY LTD", response.Registrant.Name);

            Assert.AreEqual("Z116060879386417", response.AdminContact.RegistryId);
            Assert.AreEqual("PETER TONOLI", response.AdminContact.Name);

            Assert.AreEqual("Z116060879386417", response.TechnicalContact.RegistryId);
            Assert.AreEqual("PETER TONOLI", response.TechnicalContact.Name);


            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.dreamhost.com", response.NameServers[0]);
            Assert.AreEqual("ns2.dreamhost.com", response.NameServers[1]);
            Assert.AreEqual("ns3.dreamhost.com", response.NameServers[2]);

            Assert.AreEqual(2, response.DomainStatus.Count);
            Assert.AreEqual("serverHold (Expired)", response.DomainStatus[0]);
            Assert.AreEqual("serverUpdateProhibited (Expired)", response.DomainStatus[1]);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.audns.net.au", "au", "not_found.txt");
            var response = parser.Parse("whois.audns.net.au", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(1, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.audns.net.au/au/NotFound", response.TemplateName);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.audns.net.au", "au", "found_status_registered.txt");
            var response = parser.Parse("whois.audns.net.au", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(16, response.FieldsParsed);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.audns.net.au/au/Found", response.TemplateName);

            Assert.AreEqual("google.com.au", response.DomainName.ToString());


            Assert.AreEqual(new DateTime(2014, 11, 5, 10, 35, 59), response.Updated);
            Assert.AreEqual("Google INC", response.Registrant.Name);

            Assert.AreEqual("MMR-122026", response.AdminContact.RegistryId);
            Assert.AreEqual("Domain Administrator", response.AdminContact.Name);

            Assert.AreEqual("MMR-87489", response.TechnicalContact.RegistryId);
            Assert.AreEqual("DNS Admin", response.TechnicalContact.Name);


            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            Assert.AreEqual(4, response.DomainStatus.Count);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[0]);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[1]);
            Assert.AreEqual("serverDeleteProhibited (Protected by .auLOCKDOWN)", response.DomainStatus[2]);
            Assert.AreEqual("serverUpdateProhibited (Protected by .auLOCKDOWN)", response.DomainStatus[3]);
        }
    }
}
