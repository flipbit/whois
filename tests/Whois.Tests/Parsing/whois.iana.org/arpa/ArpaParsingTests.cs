using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Iana.Org.Arpa
{
    [TestFixture]
    public class ArpaParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.iana.org", "arpa", "not_found.txt");
            var response = parser.Parse("whois.iana.org", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.iana.org/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.arpa", response.DomainName.ToString());


            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found()
        {
            var sample = SampleReader.Read("whois.iana.org", "arpa", "found.txt");
            var response = parser.Parse("whois.iana.org", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.iana.org/Found02", response.TemplateName);

            Assert.AreEqual("ip6.arpa", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2011, 07, 21, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(2001, 11, 10, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("Internet Assigned Numbers Authority (IANA)", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("4676 Admiralty Way", response.Registrant.Address[0]);
            Assert.AreEqual("Suite 330", response.Registrant.Address[1]);
            Assert.AreEqual("Marina del Rey California 90292-6610", response.Registrant.Address[2]);
            Assert.AreEqual("US", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("Internet Architecture Board (IAB)", response.AdminContact.Organization);
            Assert.AreEqual("+1 703 326 9880", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1 703 326 9881", response.AdminContact.FaxNumber);
            Assert.AreEqual("iab@iab.org", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("1775 Wiehle Ave.", response.AdminContact.Address[0]);
            Assert.AreEqual("Suite 102", response.AdminContact.Address[1]);
            Assert.AreEqual("Reston Virginia 20190-5108", response.AdminContact.Address[2]);
            Assert.AreEqual("United States", response.AdminContact.Address[3]);


             // TechnicalContact Details
            Assert.AreEqual("Internet Assigned Numbers Authority (IANA)", response.TechnicalContact.Organization);
            Assert.AreEqual("+1 310 823 9358", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1 310 823 8649", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("iana@iana.org", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("4676 Admiralty Way", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Suite 330", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Marina del Rey California 90292-6610", response.TechnicalContact.Address[2]);
            Assert.AreEqual("United States", response.TechnicalContact.Address[3]);


            // Nameservers
            Assert.AreEqual(6, response.NameServers.Count);
            Assert.AreEqual("a.ip6-servers.arpa", response.NameServers[0]);
            Assert.AreEqual("b.ip6-servers.arpa", response.NameServers[1]);
            Assert.AreEqual("c.ip6-servers.arpa", response.NameServers[2]);
            Assert.AreEqual("d.ip6-servers.arpa", response.NameServers[3]);
            Assert.AreEqual("e.ip6-servers.arpa", response.NameServers[4]);
            Assert.AreEqual("f.ip6-servers.arpa", response.NameServers[5]);

            Assert.AreEqual(31, response.FieldsParsed);
        }
    }
}
