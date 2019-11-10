using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Dns.Lu.Lu
{
    [TestFixture]
    public class LuParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.dns.lu", "lu", "found.txt");
            var response = parser.Parse("whois.dns.lu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.lu/lu/Found", response.TemplateName);

            Assert.AreEqual("arbed.lu", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Nameshield", response.Registrar.Name);
            Assert.AreEqual("http://www.nameshield.net", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2008, 08, 11, 00, 00, 00, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("ARCELORMITTAL", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("19, avenue de la liberte", response.Registrant.Address[0]);
            Assert.AreEqual("L-2930", response.Registrant.Address[1]);
            Assert.AreEqual("LUXEMBOURG", response.Registrant.Address[2]);
            Assert.AreEqual("LU", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("WEBER antoine", response.AdminContact.Name);
            Assert.AreEqual("pi@arcelormittal.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("ARCELORMITTAL LUXEMBOURG", response.AdminContact.Address[0]);
            Assert.AreEqual("19, avenue de la liberte", response.AdminContact.Address[1]);
            Assert.AreEqual("L-2930", response.AdminContact.Address[2]);
            Assert.AreEqual("LUXEMBOURG", response.AdminContact.Address[3]);
            Assert.AreEqual("LU", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("TECHNICAL Department", response.TechnicalContact.Name);
            Assert.AreEqual("technical@nameshield.net", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("NAMESHIELD", response.TechnicalContact.Address[0]);
            Assert.AreEqual("27 rue des arenes", response.TechnicalContact.Address[1]);
            Assert.AreEqual("49100", response.TechnicalContact.Address[2]);
            Assert.AreEqual("ANGERS", response.TechnicalContact.Address[3]);
            Assert.AreEqual("FR", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(3, response.NameServers.Count);
            Assert.AreEqual("ns1.arbed.lu", response.NameServers[0]);
            Assert.AreEqual("ns1.pt.lu", response.NameServers[1]);
            Assert.AreEqual("ns2.arbed.lu", response.NameServers[2]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(28, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.dns.lu", "lu", "not_found.txt");
            var response = parser.Parse("whois.dns.lu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.lu/lu/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.lu", response.DomainName.ToString());


            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.dns.lu", "lu", "found_status_registered.txt");
            var response = parser.Parse("whois.dns.lu", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.dns.lu/lu/Found", response.TemplateName);

            Assert.AreEqual("google.lu", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("Markmonitor", response.Registrar.Name);
            Assert.AreEqual("http://www.markmonitor.com/", response.Registrar.Url);

            Assert.AreEqual(new DateTime(2003, 06, 04, 00, 00, 00, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("Google Inc.", response.Registrant.Name);

             // Registrant Address
            Assert.AreEqual(4, response.Registrant.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.Registrant.Address[0]);
            Assert.AreEqual("94043", response.Registrant.Address[1]);
            Assert.AreEqual("Mountain View", response.Registrant.Address[2]);
            Assert.AreEqual("US", response.Registrant.Address[3]);


             // AdminContact Details
            Assert.AreEqual("DNS Admin", response.AdminContact.Name);
            Assert.AreEqual("dns-admin@google.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(5, response.AdminContact.Address.Count);
            Assert.AreEqual("Google Inc.", response.AdminContact.Address[0]);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.AdminContact.Address[1]);
            Assert.AreEqual("94043", response.AdminContact.Address[2]);
            Assert.AreEqual("Mountain View", response.AdminContact.Address[3]);
            Assert.AreEqual("US", response.AdminContact.Address[4]);


             // TechnicalContact Details
            Assert.AreEqual("DNS Admin", response.TechnicalContact.Name);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(5, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Address[0]);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.TechnicalContact.Address[1]);
            Assert.AreEqual("94043", response.TechnicalContact.Address[2]);
            Assert.AreEqual("Mountain View", response.TechnicalContact.Address[3]);
            Assert.AreEqual("US", response.TechnicalContact.Address[4]);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(29, response.FieldsParsed);
        }
    }
}
