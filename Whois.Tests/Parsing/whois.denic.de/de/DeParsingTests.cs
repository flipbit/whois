using System;
using NUnit.Framework;
using Whois.Parsers;

namespace Whois.Parsing.Whois.Denic.De.De
{
    [TestFixture]
    public class DeParsingTests : ParsingTests
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
            var sample = SampleReader.Read("whois.denic.de", "de", "found.txt");
            var response = parser.Parse("whois.denic.de", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.denic.de/de/Found", response.TemplateName);

            Assert.AreEqual("prodns.de", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2013, 12, 4, 13, 42, 43, DateTimeKind.Utc), response.Updated);

             // AdminContact Details
            Assert.AreEqual("Prohost Role", response.AdminContact.Name);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Koepenweg 8", response.AdminContact.Address[0]);
            Assert.AreEqual("27616", response.AdminContact.Address[1]);
            Assert.AreEqual("Lunestedt", response.AdminContact.Address[2]);
            Assert.AreEqual("DE", response.AdminContact.Address[3]);

            Assert.AreEqual("+49 4748 947983", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+49 4748 947984", response.AdminContact.FaxNumber);
            Assert.AreEqual("hostmaster@prohost.de", response.AdminContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("Prohost Role", response.TechnicalContact.Name);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Koepenweg 8", response.TechnicalContact.Address[0]);
            Assert.AreEqual("27616", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Lunestedt", response.TechnicalContact.Address[2]);
            Assert.AreEqual("DE", response.TechnicalContact.Address[3]);

            Assert.AreEqual("+49 4748 947983", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+49 4748 947984", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("hostmaster@prohost.de", response.TechnicalContact.Email);


            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("ns2.prodns.eu", response.NameServers[0]);
            Assert.AreEqual("ns4.prodns.eu", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("connect", response.DomainStatus[0]);

            Assert.AreEqual(22, response.FieldsParsed);
        }

        [Test]
        public void Test_found_technical_contact()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "found_technical_contact.txt");
            var response = parser.Parse("whois.denic.de", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.denic.de/de/Found", response.TemplateName);

            Assert.AreEqual("google.de", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2010, 9, 8, 20, 40, 48, DateTimeKind.Utc), response.Updated);

             // AdminContact Details
            Assert.AreEqual("Domain Admin", response.AdminContact.Name);
            Assert.AreEqual("MarkMonitor Inc", response.AdminContact.Organization);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("391 N Ancestor Pl", response.AdminContact.Address[0]);
            Assert.AreEqual("83704", response.AdminContact.Address[1]);
            Assert.AreEqual("Boise", response.AdminContact.Address[2]);
            Assert.AreEqual("US", response.AdminContact.Address[3]);

            Assert.AreEqual("+1.2083895740", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.2083895771", response.AdminContact.FaxNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.AdminContact.Email);

             // TechnicalContact Details
            Assert.AreEqual("DNS Admin", response.TechnicalContact.Name);
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.AreEqual("94043", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Mountain View", response.TechnicalContact.Address[2]);
            Assert.AreEqual("US", response.TechnicalContact.Address[3]);

            Assert.AreEqual("+1.6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com.", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com.", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com.", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com.", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("connect", response.DomainStatus[0]);

            Assert.AreEqual(26, response.FieldsParsed);
        }

        [Test]
        public void Test_error()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "error.txt");
            var response = parser.Parse("whois.denic.de", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Error, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.denic.de/de/Error", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_throttled()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "throttled.txt");
            var response = parser.Parse("whois.denic.de", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Throttled, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.denic.de/de/Throttled", response.TemplateName);

            Assert.AreEqual(1, response.FieldsParsed);
        }

        [Test]
        public void Test_not_found()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "not_found.txt");
            var response = parser.Parse("whois.denic.de", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.NotFound, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.denic.de/de/NotFound", response.TemplateName);

            Assert.AreEqual("u34jedzcq.de", response.DomainName.ToString());

            Assert.AreEqual(2, response.FieldsParsed);
        }

        [Test]
        public void Test_failed()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "failed.txt");
            var response = parser.Parse("whois.denic.de", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Failed, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.denic.de/de/Found", response.TemplateName);

            Assert.AreEqual("msens.de", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2011, 2, 23, 4, 36, 15, DateTimeKind.Utc), response.Updated);

             // AdminContact Details
            Assert.AreEqual("Daniel Andersson", response.AdminContact.Name);
            Assert.AreEqual("GUIDANCE INTERNATIONAL IP AB", response.AdminContact.Organization);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Landerigatan 1", response.AdminContact.Address[0]);
            Assert.AreEqual("50451", response.AdminContact.Address[1]);
            Assert.AreEqual("Borås", response.AdminContact.Address[2]);
            Assert.AreEqual("SE", response.AdminContact.Address[3]);

            Assert.AreEqual("+46.701434896", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+46.701434896", response.AdminContact.FaxNumber);
            Assert.AreEqual("info@guid-int.com", response.AdminContact.Email);

             // TechnicalContact Details
            Assert.AreEqual("Daniel Andersson", response.TechnicalContact.Name);
            Assert.AreEqual("GUIDANCE INTERNATIONAL IP AB", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Landerigatan 1", response.TechnicalContact.Address[0]);
            Assert.AreEqual("50451", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Borås", response.TechnicalContact.Address[2]);
            Assert.AreEqual("SE", response.TechnicalContact.Address[3]);

            Assert.AreEqual("+46.701434896", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+46.701434896", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("info@guid-int.com", response.TechnicalContact.Email);

            // Nameservers
            Assert.AreEqual(2, response.NameServers.Count);
            Assert.AreEqual("newreg-ns1.premiumregistrations.com", response.NameServers[0]);
            Assert.AreEqual("newreg-ns2.premiumregistrations.com", response.NameServers[1]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("failed", response.DomainStatus[0]);

            Assert.AreEqual(24, response.FieldsParsed);
        }

        [Test]
        public void Test_failed_status_failed_ace()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "failed_status_failed_ace.txt");
            var response = parser.Parse("whois.denic.de", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Failed, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.denic.de/de/Found", response.TemplateName);

            Assert.AreEqual("xn--tstdomain-failed-nserver-qbc.de", response.DomainName.ToString());
            Assert.AreEqual("tästdomain-failed-nserver.de", response.DomainName.ToUnicodeString());

            Assert.AreEqual(new DateTime(2010, 6, 1, 8, 29, 38, DateTimeKind.Utc), response.Updated);

             // AdminContact Details
            Assert.AreEqual("Business Services", response.AdminContact.Name);
            Assert.AreEqual("DENIC eG", response.AdminContact.Organization);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("Kaiserstrasse 75-77", response.AdminContact.Address[0]);
            Assert.AreEqual("60329", response.AdminContact.Address[1]);
            Assert.AreEqual("Frankfurt am Main", response.AdminContact.Address[2]);
            Assert.AreEqual("DE", response.AdminContact.Address[3]);

            Assert.AreEqual("+49 69 27235 272", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+49 69 27235 234", response.AdminContact.FaxNumber);
            Assert.AreEqual("dbs@denic.de", response.AdminContact.Email);


             // TechnicalContact Details
            Assert.AreEqual("Business Services", response.TechnicalContact.Name);
            Assert.AreEqual("DENIC eG", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("Kaiserstrasse 75-77", response.TechnicalContact.Address[0]);
            Assert.AreEqual("60329", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Frankfurt am Main", response.TechnicalContact.Address[2]);
            Assert.AreEqual("DE", response.TechnicalContact.Address[3]);

            Assert.AreEqual("+49 69 27235 272", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+49 69 27235 234", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dbs@denic.de", response.TechnicalContact.Email);


            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.denic.de.", response.NameServers[0]);
            Assert.AreEqual("ns2.denic.de.", response.NameServers[1]);
            Assert.AreEqual("ns3.denic.de.", response.NameServers[2]);
            Assert.AreEqual("ns4.denic.net.", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("failed", response.DomainStatus[0]);

            Assert.AreEqual(26, response.FieldsParsed);
        }

        [Test]
        public void Test_invalid()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "invalid.txt");
            var response = parser.Parse("whois.denic.de", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Invalid, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.denic.de/de/Invalid", response.TemplateName);

            Assert.AreEqual("googlededewdedewdewde.foo.de", response.DomainName.ToString());

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("invalid", response.DomainStatus[0]);

            Assert.AreEqual(3, response.FieldsParsed);
        }

        [Test]
        public void Test_found_status_registered()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "found_status_registered.txt");
            var response = parser.Parse("whois.denic.de", sample);

            Assert.Greater(sample.Length, 0);
            Assert.AreEqual(WhoisStatus.Found, response.Status);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.denic.de/de/Found", response.TemplateName);

            Assert.AreEqual("google.de", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2011, 3, 30, 17, 36, 27, DateTimeKind.Utc), response.Updated);

             // AdminContact Details
            Assert.AreEqual("Domain Admin", response.AdminContact.Name);
            Assert.AreEqual("MarkMonitor Inc", response.AdminContact.Organization);

             // AdminContact Address
            Assert.AreEqual(4, response.AdminContact.Address.Count);
            Assert.AreEqual("391 N Ancestor Pl", response.AdminContact.Address[0]);
            Assert.AreEqual("83704", response.AdminContact.Address[1]);
            Assert.AreEqual("Boise", response.AdminContact.Address[2]);
            Assert.AreEqual("US", response.AdminContact.Address[3]);

            Assert.AreEqual("+1.2083895740", response.AdminContact.TelephoneNumber);
            Assert.AreEqual("+1.2083895771", response.AdminContact.FaxNumber);
            Assert.AreEqual("ccops@markmonitor.com", response.AdminContact.Email);

             // TechnicalContact Details
            Assert.AreEqual("DNS Admin", response.TechnicalContact.Name);
            Assert.AreEqual("Google Inc.", response.TechnicalContact.Organization);

             // TechnicalContact Address
            Assert.AreEqual(4, response.TechnicalContact.Address.Count);
            Assert.AreEqual("1600 Amphitheatre Parkway", response.TechnicalContact.Address[0]);
            Assert.AreEqual("94043", response.TechnicalContact.Address[1]);
            Assert.AreEqual("Mountain View", response.TechnicalContact.Address[2]);
            Assert.AreEqual("US", response.TechnicalContact.Address[3]);

            Assert.AreEqual("+1.6502530000", response.TechnicalContact.TelephoneNumber);
            Assert.AreEqual("+1.6506188571", response.TechnicalContact.FaxNumber);
            Assert.AreEqual("dns-admin@google.com", response.TechnicalContact.Email);

            // Nameservers
            Assert.AreEqual(4, response.NameServers.Count);
            Assert.AreEqual("ns1.google.com", response.NameServers[0]);
            Assert.AreEqual("ns2.google.com", response.NameServers[1]);
            Assert.AreEqual("ns3.google.com", response.NameServers[2]);
            Assert.AreEqual("ns4.google.com", response.NameServers[3]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("connect", response.DomainStatus[0]);

            Assert.AreEqual(26, response.FieldsParsed);
        }
        
        [Test]
        public void Test_found_amazon_de()
        {
            var sample = SampleReader.Read("whois.denic.de", "de", "amazon.de.txt");
            
            var response = parser.Parse("whois.denic.de", sample);

            Assert.AreEqual(0, response.ParsingErrors);
            Assert.AreEqual("whois.denic.de/de/Found", response.TemplateName);

            Assert.AreEqual("amazon.de", response.DomainName.ToString());

            Assert.AreEqual(new DateTime(2018, 8, 10, 8, 41, 26, DateTimeKind.Utc), response.Updated);

            // Nameservers
            Assert.AreEqual(6, response.NameServers.Count);
            Assert.AreEqual("ns1.p31.dynect.net", response.NameServers[0]);
            Assert.AreEqual("ns2.p31.dynect.net", response.NameServers[1]);
            Assert.AreEqual("ns3.p31.dynect.net", response.NameServers[2]);
            Assert.AreEqual("ns4.p31.dynect.net", response.NameServers[3]);
            Assert.AreEqual("pdns1.ultradns.net", response.NameServers[4]);
            Assert.AreEqual("pdns6.ultradns.co.uk", response.NameServers[5]);

            // Domain Status
            Assert.AreEqual(1, response.DomainStatus.Count);
            Assert.AreEqual("connect", response.DomainStatus[0]);

            Assert.AreEqual(10, response.FieldsParsed);
        }
    }
}
