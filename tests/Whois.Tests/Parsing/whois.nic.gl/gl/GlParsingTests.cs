using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Nic.Gl.Gl
{
    [TestFixture]
    public class GlParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.nic.gl", "gl", "not_found.txt");
            var response = parser.Parse("whois.nic.gl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/NotFound004", response.TemplateName);

            Assert.AreEqual("u34jedzcq.gl", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.nic.gl", "gl", "found.txt");
            var response = parser.Parse("whois.nic.gl", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("generic/tld/Found001", response.TemplateName);

            Assert.AreEqual("google.gl", response.DomainName.ToString());
            Assert.AreEqual("Imp669-GL", response.RegistryDomainId);

            // Registrar Details
            Assert.AreEqual("MarkMonitor", response.Registrar.Name);
            Assert.AreEqual("http://www.markmonitor.com", response.Registrar.Url);
            Assert.AreEqual("ccops@markmonitor.com", response.Registrar.AbuseEmail);

            Assert.AreEqual(new DateTime(2013, 12, 02, 19, 11, 52, 734, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2003, 03, 11, 03, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2015, 01, 01, 03, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("4738-GL", response.Registrant.RegistryId);
            Assert.AreEqual("Google Inc.", response.Registrant.Name);
            Assert.AreEqual("+1.6303300100", response.Registrant.TelephoneNumber);
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

             // Registrant Address
            Assert.AreEqual(5, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[1]);
            Assert.AreEqual("CA", response.Registrant.Address[2]);
            Assert.AreEqual("94043", response.Registrant.Address[3]);
            Assert.AreEqual("US", response.Registrant.Address[4]);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(5, response.DomainStatus.Count);
            Assert.AreEqual("clientRenewProhibited", response.DomainStatus[0]);
            Assert.AreEqual("clientDeleteProhibited", response.DomainStatus[1]);
            Assert.AreEqual("clientTransferProhibited", response.DomainStatus[2]);
            Assert.AreEqual("ok", response.DomainStatus[3]);
            Assert.AreEqual("clientUpdateProhibited", response.DomainStatus[4]);

            Assert.AreEqual("unsigned", response.DnsSecStatus);
            Assert.AreEqual(27, response.FieldsParsed);
        }
    }
}
