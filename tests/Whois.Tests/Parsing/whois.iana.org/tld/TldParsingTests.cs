using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Iana.Org.Tld
{
    [TestFixture]
    public class TldParsingTests : ParsingTests
    {
        private WhoisParser parser;

        [SetUp]
        public void SetUp()
        {
            SerilogConfig.Init();

            parser = new WhoisParser();
        }

        [Test]
        public void Test_found_be()
        {
            var sample = SampleReader.Read("whois.iana.org", "tld", "be.txt");
            var response = parser.Parse("whois.iana.org", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.iana.org/Found01", response.TemplateName);

            Assert.AreEqual("be", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("whois.dns.be", response.Registrar.WhoisServer.Value);

            Assert.AreEqual(new DateTime(2014, 07, 30, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1988, 08, 05, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("DNS Belgium vzw/asbl", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("Ubicenter, Philipssite 5, bus 13", response.Registrant.Address[0]);
            Assert.AreEqual("Leuven  3001", response.Registrant.Address[1]);
            Assert.AreEqual("Belgium", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("Philip Du Bois", response.AdminContact.Name);
            Assert.AreEqual("+32 16 28 49 70", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+32 16 28 49 71", response.AdminContact.FaxNumber);
            Assert.AreEqual("legal@dnsbelgium.be", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("Ubicenter, Philipssite 5, bus 13", response.AdminContact.Address[0]);
            Assert.AreEqual("Leuven  3001", response.AdminContact.Address[1]);
            Assert.AreEqual("Belgium", response.AdminContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("David Goelen", response.TechnicalContact.Name);
            Assert.AreEqual("+32 16 28 49 70", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+32 16 28 49 71", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("tech@dnsbelgium.be", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Ubicenter, Philipssite 5, bus 13", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Leuven  3001", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Belgium", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(6, response.NameServers.Count);
            Assert.AreEqual("a.ns.dns.be", response.NameServers[0]);
            Assert.AreEqual("b.ns.dns.be", response.NameServers[1]);
            Assert.AreEqual("c.ns.dns.be", response.NameServers[2]);
            Assert.AreEqual("d.ns.dns.be", response.NameServers[3]);
            Assert.AreEqual("x.ns.dns.be", response.NameServers[4]);
            Assert.AreEqual("y.ns.dns.be", response.NameServers[5]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(33, response.FieldsParsed);
        }

        [Test]
        public void Test_found_com()
        {
            var sample = SampleReader.Read("whois.iana.org", "tld", "com.txt");
            var response = parser.Parse("whois.iana.org", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.iana.org/Found01", response.TemplateName);

            Assert.AreEqual("com", response.DomainName.ToString());

            // Registrar Details
            Assert.AreEqual("whois.verisign-grs.com", response.Registrar.WhoisServer.Value);

            Assert.AreEqual(new DateTime(2012, 02, 15, 00, 00, 00, 000, DateTimeKind.Utc), response.Updated);
            Assert.AreEqual(new DateTime(1985, 01, 01, 00, 00, 00, 000, DateTimeKind.Utc), response.Registered);

             // Registrant Details
            Assert.AreEqual("VeriSign Global Registry Services", response.Registrant.Organization);

             // Registrant Address
            Assert.AreEqual(3, response.Registrant.Address.Count);
            Assert.AreEqual("12061 Bluemont Way", response.Registrant.Address[0]);
            Assert.AreEqual("Reston Virginia 20190", response.Registrant.Address[1]);
            Assert.AreEqual("United States", response.Registrant.Address[2]);


             // AdminContact Details
            Assert.AreEqual("Registry Customer Service", response.AdminContact.Name);
            Assert.AreEqual("+1 703 925-6999", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1 703 948 3978", response.AdminContact.FaxNumber);
            Assert.AreEqual("info@verisign-grs.com", response.AdminContact.Email);

             // AdminContact Address
            Assert.AreEqual(3, response.AdminContact.Address.Count);
            Assert.AreEqual("12061 Bluemont Way", response.AdminContact.Address[0]);
            Assert.AreEqual("Reston Virginia 20190", response.AdminContact.Address[1]);
            Assert.AreEqual("United States", response.AdminContact.Address[2]);


             // TechnicalContact Details
            Assert.AreEqual("Registry Customer Service", response.TechnicalContact.Name);
            Assert.AreEqual("+1 703 925-6999", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1 703 948 3978", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("info@verisign-grs.com", response.TechnicalContact.Email);

             // TechnicalContact Address
            Assert.AreEqual(3, response.TechnicalContact.Address.Count);
            Assert.AreEqual("12061 Bluemont Way", response.TechnicalContact.Address[0]);
            Assert.AreEqual("Reston Virginia 20190", response.TechnicalContact.Address[1]);
            Assert.AreEqual("United States", response.TechnicalContact.Address[2]);


            // Nameservers
            Assert.AreEqual(13, response.NameServers.Count);
            Assert.AreEqual("a.gtld-servers.net", response.NameServers[0]);
            Assert.AreEqual("b.gtld-servers.net", response.NameServers[1]);
            Assert.AreEqual("c.gtld-servers.net", response.NameServers[2]);
            Assert.AreEqual("d.gtld-servers.net", response.NameServers[3]);
            Assert.AreEqual("e.gtld-servers.net", response.NameServers[4]);
            Assert.AreEqual("f.gtld-servers.net", response.NameServers[5]);
            Assert.AreEqual("g.gtld-servers.net", response.NameServers[6]);
            Assert.AreEqual("h.gtld-servers.net", response.NameServers[7]);
            Assert.AreEqual("i.gtld-servers.net", response.NameServers[8]);
            Assert.AreEqual("j.gtld-servers.net", response.NameServers[9]);
            Assert.AreEqual("k.gtld-servers.net", response.NameServers[10]);
            Assert.AreEqual("l.gtld-servers.net", response.NameServers[11]);
            Assert.AreEqual("m.gtld-servers.net", response.NameServers[12]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("ACTIVE", response.DomainStatus[0]);

            Assert.AreEqual(40, response.FieldsParsed);
        }

        [Test]
        public void Test_not_assigned()
        {
            var sample = SampleReader.Read("whois.iana.org", "tld", "not_assigned.txt");
            var response = parser.Parse("whois.iana.org", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotAssigned, response.Status);

            AssertWriter.Write(response);
        }
    }
}
