using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Domreg.Lt.Lt
{
    [TestFixture]
    public class LtParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.domreg.lt", "lt", "found.txt");
            var response = parser.Parse("whois.domreg.lt", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.domreg.lt/lt/Found", response.TemplateName);

            Assert.AreEqual("serveriai.lt", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual(@"UAB ""Interneto vizija""", response.Registrar.Name);
            Assert.AreEqual("http://www.iv.lt/", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2003, 11, 17, 00, 00, 00, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual(@"UAB ""Interneto vizija""", response.Registrant.Organization);
            Assert.AreEqual("hostmaster@iv.lt", response.Registrant.Email);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("registered", response.DomainStatus[0]);

            Assert.AreEqual(8, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.domreg.lt", "lt", "not_found.txt");
            var response = parser.Parse("whois.domreg.lt", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.domreg.lt/lt/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.lt", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.domreg.lt", "lt", "found_status_registered.txt");
            var response = parser.Parse("whois.domreg.lt", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.domreg.lt/lt/Found", response.TemplateName);

            Assert.AreEqual("google.lt", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("MarkMonitor, Inc.", response.Registrar.Name);
            Assert.AreEqual("http://www.markmonitor.com", response.Registrar.Url);

            Assert.AreEqual(new DateTime(1999, 06, 06, 00, 00, 00, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("dns-admin@google.com", response.Registrant.Email);

            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("registered", response.DomainStatus[0]);

            Assert.AreEqual(10, response.FieldsParsed);
        }
    }
}
