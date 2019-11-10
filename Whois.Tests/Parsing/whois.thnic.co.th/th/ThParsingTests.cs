using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Thnic.Co.Th.Th
{
    [TestFixture]
    public class ThParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.thnic.co.th", "th", "not_found.txt");
            var response = parser.Parse("whois.thnic.co.th", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.thnic.co.th/th/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.co.th", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.thnic.co.th", "th", "found.txt");
            var response = parser.Parse("whois.thnic.co.th", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            AssertWriter.Write(response);
            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.thnic.co.th/th/Found", response.TemplateName);

            Assert.AreEqual("google.co.th", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("T.H.NIC Co., Ltd.", response.Registrar.Name);

            Assert.AreEqual(new DateTime(2012, 09, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2004, 10, 08, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);
            Assert.AreEqual(new DateTime(2013, 10, 07, 00, 00, 00, 000, DateTimeKind.Utc), response.Expiration);

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("2400 Bayshore Parkway, Mountain Veiw, CA", response.Registrant.Address[0]);
            Assert.AreEqual("94043", response.Registrant.Address[1]);
            Assert.AreEqual("US", response.Registrant.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("13244", response.TechnicalContact.RegistryId);
            Assert.AreEqual("MarkMonitor Inc.", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("391 N Ancestor Place, Boise, ID", response.TechnicalContact.Address[0]);
            Assert.AreEqual("83704", response.TechnicalContact.Address[1]);
            Assert.AreEqual("US", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(20, response.FieldsParsed);
        }
    }
}
